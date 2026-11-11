#!/usr/bin/env python3
"""Benchmark create -> pause -> resume -> delete, each in strict batches.

Uses E2B AsyncSandbox.create/pause/connect/kill directly. No operation retries.
Every benchmark first creates, pauses, resumes and deletes one warmup sandbox in the same event
loop. Warmup must succeed and is excluded from the requested total and averages.
--total is the sandbox count per round; --rounds repeats the full lifecycle.
Each round deletes its sandboxes before the next round starts.
Latency is SDK call start to return, excluding argument preparation, batch
queueing, logging and statistics. SDK internals/network/server time are included.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
import csv
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import signal
import statistics
import time
import uuid


LATENCY_DEFINITION = (
    "SDK create/pause/connect(resume)/kill call start to return (perf_counter seconds); excludes argument "
    "preparation, batch queueing, logging and statistics; includes SDK internals, "
    "network, server processing and scheduling during await"
)


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def load_images(path):
    mapping = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("image map must be a non-empty {trajectory: image/template} object")
    images = []
    for key, value in mapping.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"invalid image/template for {key!r}: expected non-empty string")
        images.append(value.strip())
    return sorted(set(images))


def stats(rows, phase):
    selected = [r for r in rows if r["phase"] == phase]
    values = sorted(r["elapsed_sec"] for r in selected if r["status"] == "ok")
    return {
        "attempted": len(selected),
        "succeeded": len(values),
        "failed": sum(r["status"] == "error" for r in selected),
        "already_absent": sum(r["status"] == "already_absent" for r in selected),
        "already_paused": sum(r["status"] == "already_paused" for r in selected),
        "mean_sec": statistics.mean(values) if values else None,
        "min_sec": min(values) if values else None,
        "max_sec": max(values) if values else None,
        "p50_sec": statistics.median(values) if values else None,
        "p95_sec": values[math.ceil(len(values) * .95) - 1] if values else None,
    }


def wall_stats(batches, phase):
    per_round = {}
    for batch in batches:
        if batch["phase"] == phase:
            round_number = batch["round"]
            per_round[round_number] = per_round.get(round_number, 0.0) + batch["wall_sec"]
    return {
        "wall_total_sec": sum(per_round.values()),
        "wall_mean_per_round_sec": statistics.mean(per_round.values()) if per_round else None,
        "wall_rounds_attempted": len(per_round),
    }


def round_wall_stats(round_results, phase):
    # Only completed, fully successful measured rounds are comparable.
    values = sorted(r[phase]["wall_sec"] for r in round_results if r["valid"])
    return {
        "round_wall_mean_sec": statistics.mean(values) if values else None,
        "round_wall_p50_sec": statistics.median(values) if values else None,
        "round_wall_p95_sec": values[math.ceil(len(values) * .95) - 1] if values else None,
        "round_wall_samples": len(values),
        "round_wall_excluded": len(round_results) - len(values),
    }


class Benchmark:
    def __init__(self, config, output):
        self.config, self.output = config, output
        self.rows, self.batches = [], []
        self.round_results = []
        self.current_round = 0
        self.live = {}
        self.paused = {}
        self.errors = []
        self.stop = False
        self.started = time.perf_counter()
        self.journal = (output / "operations.jsonl").open("a", encoding="utf-8", buffering=1)

    def record(self, row):
        self.rows.append(row)

    async def operation(self, phase, item, batch):
        from e2b import AsyncSandbox

        row = dict(item, phase=phase, batch=batch, started_at=now(), status="error", error="",
                   elapsed_sec=None)
        row.setdefault("round", self.current_round)
        request_timeout = self.config["request_timeout"]
        try:
            if phase in ("create", "warmup_create"):
                template = item["image"]
                sandbox_timeout = self.config["sandbox_timeout"]
                metadata = {
                    "lifecycle_benchmark_run": self.config["run_id"],
                    "lifecycle_benchmark_index": str(item["index"]),
                    "lifecycle_benchmark_round": str(row["round"]),
                }
                async with asyncio.timeout(request_timeout):
                    create_started = time.perf_counter()
                    try:
                        sandbox = await AsyncSandbox.create(
                            template=template,
                            metadata=metadata,
                            timeout=sandbox_timeout,
                            request_timeout=request_timeout,
                        )
                    finally:
                        row["elapsed_sec"] = time.perf_counter() - create_started
                sandbox_id = sandbox.sandbox_id
                row["sandbox_id"] = sandbox_id
                self.live[sandbox_id] = dict(item, sandbox_id=sandbox_id, round=row["round"])
                row["status"] = "ok"
            elif phase in ("pause", "warmup_pause"):
                sandbox_id = item["sandbox_id"]
                async with asyncio.timeout(request_timeout):
                    pause_started = time.perf_counter()
                    try:
                        paused = await AsyncSandbox.pause(
                            sandbox_id,
                            keep_memory=True,
                            request_timeout=request_timeout,
                        )
                    finally:
                        row["elapsed_sec"] = time.perf_counter() - pause_started
                if paused:
                    self.paused[sandbox_id] = dict(item)
                row["status"] = "ok" if paused else "already_paused"
            elif phase in ("resume", "warmup_resume"):
                sandbox_id = item["sandbox_id"]
                sandbox_timeout = self.config["sandbox_timeout"]
                # connect() is the SDK's resume API. Only resume confirmed pauses.
                if sandbox_id not in self.paused:
                    raise RuntimeError("Cannot measure resume without a successful pause")
                async with asyncio.timeout(request_timeout):
                    resume_started = time.perf_counter()
                    try:
                        sandbox = await AsyncSandbox.connect(
                            sandbox_id,
                            timeout=sandbox_timeout,
                            request_timeout=request_timeout,
                        )
                    finally:
                        row["elapsed_sec"] = time.perf_counter() - resume_started
                if sandbox.sandbox_id != sandbox_id:
                    raise RuntimeError("Resume returned a different sandbox ID")
                self.paused.pop(sandbox_id, None)
                row["status"] = "ok"
            elif phase in ("delete", "warmup_delete", "cleanup"):
                sandbox_id = item["sandbox_id"]
                async with asyncio.timeout(request_timeout):
                    delete_started = time.perf_counter()
                    try:
                        deleted = await AsyncSandbox.kill(
                            sandbox_id,
                            request_timeout=request_timeout,
                        )
                    finally:
                        row["elapsed_sec"] = time.perf_counter() - delete_started
                self.live.pop(sandbox_id, None)
                self.paused.pop(sandbox_id, None)
                row["status"] = "ok" if deleted else "already_absent"
            else:
                raise ValueError(f"Unknown lifecycle phase: {phase}")
        except Exception as exc:
            row["error"] = f"{type(exc).__name__}: {exc}"
        row["completed_at"] = now()
        self.record(row)

    async def batches_for(self, phase, items, respect_stop=False):
        size = self.config["batch_size"]
        for start in range(0, len(items), size):
            if respect_stop and self.stop:
                break
            batch = start // size + 1
            chunk = items[start:start + size]
            offset = len(self.rows)
            started = time.perf_counter()
            # Barrier: no task from the next batch is submitted until ALL finish.
            await asyncio.gather(*(self.operation(phase, item, batch) for item in chunk))
            wall_sec = time.perf_counter() - started
            # All SDK operations have finished before any synchronous file I/O.
            for row in self.rows[offset:]:
                self.journal.write(json.dumps(row, ensure_ascii=False) + "\n")
            self.journal.flush()
            report = dict(round=self.current_round, phase=phase, batch=batch,
                          wall_sec=wall_sec,
                          **stats(self.rows[offset:], phase))
            self.batches.append(report)
            self.save()
            latency_text = ", ".join(
                f"{label}={report[key]:.6f} sec" if report[key] is not None
                else f"{label}=N/A"
                for label, key in (
                    ("mean", "mean_sec"), ("P50", "p50_sec"), ("P95", "p95_sec")
                )
            )
            print(f"round {self.current_round} {phase} batch {batch}: {report['succeeded']}/{len(chunk)} OK, "
                  f"{latency_text}, "
                  f"wall={report['wall_sec']:.3f} sec", flush=True)

    async def discover(self):
        """Recover IDs after lost responses; filter both server-side and locally."""
        from e2b import AsyncSandbox
        from e2b.sandbox.sandbox_api import SandboxQuery

        async def lookup():
            pager = AsyncSandbox.list(
                query=SandboxQuery(metadata={"lifecycle_benchmark_run": self.config["run_id"]}),
                limit=100, request_timeout=self.config["request_timeout"])
            found = {}
            while pager.has_next:
                for sandbox in await pager.next_items():
                    metadata = sandbox.metadata or {}
                    if metadata.get("lifecycle_benchmark_run") != self.config["run_id"]:
                        continue
                    found[sandbox.sandbox_id] = {
                        "index": metadata.get("lifecycle_benchmark_index", "unknown"),
                        "image": getattr(sandbox, "template_id", "unknown"),
                        "sandbox_id": sandbox.sandbox_id,
                        "round": int(metadata.get("lifecycle_benchmark_round", "0" if metadata.get("lifecycle_benchmark_index") == "0" else "1")),
                    }
            return found
        return await asyncio.wait_for(lookup(), timeout=self.config["request_timeout"])

    async def warmup(self, image):
        print("Warmup: create -> pause -> resume -> delete 1 sandbox; excluded from benchmark statistics.", flush=True)
        await self.batches_for("warmup_create", [{"index": 0, "image": image, "round": 0}])
        if stats(self.rows, "warmup_create")["succeeded"] != 1:
            self.errors.append("Warmup creation failed; measured batches were not started.")
            return False
        for phase in ("warmup_pause", "warmup_resume", "warmup_delete"):
            await self.batches_for(phase, list(self.live.values()))
            if stats(self.rows, phase)["succeeded"] != 1:
                self.errors.append(f"{phase} failed; measured batches were not started.")
                return False
        print("Warmup completed. Starting measured batches.", flush=True)
        return True

    def save(self, final=False):
        create, delete = stats(self.rows, "create"), stats(self.rows, "delete")
        pause, resume = stats(self.rows, "pause"), stats(self.rows, "resume")
        for phase, result in (("create", create), ("pause", pause), ("resume", resume), ("delete", delete)):
            result.update(wall_stats(self.batches, phase))
            result.update(round_wall_stats(self.round_results, phase))
        round_wall_times = [result["wall_sec"] for result in self.round_results]
        rounds_requested = self.config.get("rounds", 1)
        expected_count = self.config["total"] * rounds_requested
        valid = (final and not self.config.get("cleanup_only") and not self.stop
                 and len(self.round_results) == rounds_requested
                 and all(result["valid"] for result in self.round_results)
                 and create["succeeded"] == expected_count
                 and delete["succeeded"] == expected_count
                 and pause["succeeded"] == expected_count
                 and resume["succeeded"] == expected_count
                 and stats(self.rows, "warmup_create")["succeeded"] == 1
                 and stats(self.rows, "warmup_pause")["succeeded"] == 1
                 and stats(self.rows, "warmup_resume")["succeeded"] == 1
                 and stats(self.rows, "warmup_delete")["succeeded"] == 1
                 and not self.live and not self.errors)
        summary = {
            "config": self.config, "final": final, "valid": valid,
            "interrupted": self.stop, "elapsed_wall_sec": time.perf_counter() - self.started,
            "create": create, "pause": pause, "resume": resume, "delete": delete,
            "warmup": {"create": stats(self.rows, "warmup_create"),
                       "pause": stats(self.rows, "warmup_pause"),
                       "resume": stats(self.rows, "warmup_resume"),
                       "delete": stats(self.rows, "warmup_delete")},
            "cleanup": stats(self.rows, "cleanup"),
            "remaining_sandboxes": list(self.live.values()), "errors": self.errors,
            "batches": self.batches,
            "rounds_requested": rounds_requested,
            "rounds_attempted": len(self.round_results),
            "rounds_succeeded": sum(result["valid"] for result in self.round_results),
            "rounds": self.round_results,
            "measured_rounds_wall_total_sec": sum(round_wall_times),
            "measured_rounds_wall_mean_sec": statistics.mean(round_wall_times) if round_wall_times else None,
            "wall_definition": "Per-operation wall_total_sec sums measured batch wall times; wall_mean_per_round_sec averages each attempted round's sum of batch wall times. Includes failed batches, excludes warmup, cleanup and between-batch reporting. Measured lifecycle round walls include between-batch reporting; elapsed_wall_sec also includes warmup and final cleanup/checks.",
            "round_statistics_definition": "round_wall_mean_sec, round_wall_p50_sec and round_wall_p95_sec use one phase wall_sec per completed valid measured round; warmup, cleanup, failed and interrupted rounds are excluded. A round phase wall_sec sums its batch walls, excluding between-batch reporting. P50 is the median; P95 uses nearest rank. mean_sec remains the mean of successful individual SDK call latencies.",
            "averaging_definition": "Each operation mean_sec is total successful SDK latency across measured rounds divided by successful sample count; warmup and cleanup are excluded.",
            "by_image": {image: {phase: stats([r for r in self.rows if r["image"] == image], phase)
                                  for phase in ("create", "pause", "resume", "delete")}
                         for image in sorted({r["image"] for r in self.rows})},
            "latency_definition": LATENCY_DEFINITION,
        }
        write_json(self.output / "summary.json", summary)
        write_json(self.output / "remaining.json", list(self.live.values()))
        columns = ["round", "phase", "batch", "index", "image", "sandbox_id", "status", "elapsed_sec",
                   "started_at", "completed_at", "error"]
        with (self.output / "operations.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            writer.writerows(self.rows)
        return summary

    async def run(self, plan):
        try:
            if not self.config.get("cleanup_only") and not self.stop:
                if await self.warmup(plan[0]["image"]):
                    for round_number in range(1, self.config.get("rounds", 1) + 1):
                        if self.stop:
                            break
                        self.current_round = round_number
                        print(f"Starting round {round_number}/{self.config.get('rounds', 1)}", flush=True)
                        offset = len(self.rows)
                        round_started = time.perf_counter()
                        round_plan = [dict(item, round=round_number) for item in plan]
                        try:
                            await self.batches_for("create", round_plan, respect_stop=True)
                            await self.batches_for("pause", list(self.live.values()), respect_stop=True)
                            await self.batches_for("resume", list(self.paused.values()), respect_stop=True)
                        finally:
                            # Finish deletion before starting another round, even on interruption.
                            measured_sandboxes = [item for item in self.live.values() if str(item["index"]) != "0"]
                            await self.batches_for("delete", measured_sandboxes)
                        round_stats = {phase: stats(self.rows[offset:], phase)
                                       for phase in ("create", "pause", "resume", "delete")}
                        round_batches = [batch for batch in self.batches if batch["round"] == round_number]
                        for phase, result in round_stats.items():
                            result["wall_sec"] = wall_stats(round_batches, phase)["wall_total_sec"]
                        round_valid = (not self.stop and not self.live
                                       and all(result["succeeded"] == self.config["total"]
                                               for result in round_stats.values()))
                        self.round_results.append({"round": round_number, "valid": round_valid,
                                                   "wall_sec": time.perf_counter() - round_started,
                                                   **round_stats})
                        self.save()
                        print(f"Round {round_number} summary: " + ", ".join(
                            f"{phase} mean={result['mean_sec']} sec wall={result['wall_sec']:.6f} sec"
                            for phase, result in round_stats.items()), flush=True)
                        if not round_valid:
                            self.errors.append(f"Round {round_number} failed or was interrupted; later rounds were not started.")
                            break
        finally:
            # Only our IDs are cleaned; recovery attempts are not measured deletions.
            if self.config.get("cleanup_only"):
                await self.batches_for("cleanup", list(self.live.values()))
            try:
                found = await self.discover()
                for sid, item in found.items():
                    self.live.setdefault(sid, item)
                if self.live:
                    await self.batches_for("cleanup", list(self.live.values()))
                remaining = await self.discover()
                # A successful inventory is authoritative about remaining IDs.
                self.live = remaining
                if remaining:
                    self.errors.append("Some test sandboxes remain; rerun with --cleanup-run.")
            except Exception as exc:
                self.errors.append(f"Final inventory/cleanup verification failed: {exc}")
            if stats(self.rows, "create")["failed"] or stats(self.rows, "warmup_create")["failed"]:
                self.errors.append("Create failures may have late server-side completion. "
                                   "No automatic create retries; run --cleanup-run again if needed.")
            summary = self.save(final=True)
            self.journal.close()
        return summary


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-map", type=Path,
                        default=Path(__file__).with_name("delay_time_trajectory_image_map.json"))
    parser.add_argument("--total", type=int, default=500, help="Measured sandboxes per round (default: 500)")
    parser.add_argument("--rounds", type=int, default=1, help="Full lifecycle rounds after one mandatory warmup (default: 1)")
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--api-url", default=os.getenv("E2B_API_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--request-timeout", type=float, default=600)
    parser.add_argument("--sandbox-timeout", type=int, default=86400,
                        help="Lifetime seconds, long enough for ALL create/delete batches (default: 86400)")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--dry-run", action="store_true", help="Write plan only; make no API calls")
    parser.add_argument("--cleanup-run", type=Path, help="Only clean sandboxes tagged with a previous output's run ID")
    args = parser.parse_args()
    if args.total < 1 or args.rounds < 1 or args.batch_size < 1 or not math.isfinite(args.request_timeout) or args.request_timeout <= 0:
        parser.error("total, rounds, batch-size and request-timeout must be positive")
    minimum_lifetime = 4 * math.ceil(args.total / args.batch_size) * args.request_timeout + 300
    if not args.cleanup_run and args.sandbox_timeout < minimum_lifetime:
        parser.error(f"sandbox-timeout must be >= {minimum_lifetime:g} to cover the complete batch run")
    return args


async def main_async(args):
    run_id = "lifecycle-" + datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
    config = dict(run_id=run_id, total=args.total, rounds=args.rounds, batch_size=args.batch_size,
                  total_measured_sandboxes=args.total * args.rounds,
                  api_url=args.api_url, request_timeout=args.request_timeout,
                  sandbox_timeout=args.sandbox_timeout, created_at=now(), cleanup_only=False,
                  warmup_count=1,
                  phases=["create", "pause", "resume", "delete"], pause_keep_memory=True,
                  latency_definition=LATENCY_DEFINITION)
    plan = []
    if args.cleanup_run:
        previous = json.loads((args.cleanup_run / "config.json").read_text(encoding="utf-8"))
        config.update(run_id=previous["run_id"], api_url=previous["api_url"], cleanup_only=True,
                      warmup_count=0, rounds=0, total_measured_sandboxes=0)
    else:
        images = load_images(args.image_map)
        plan = [{"index": i + 1, "image": images[i % len(images)]} for i in range(args.total)]
        config.update(image_map=str(args.image_map.resolve()), unique_images=len(images),
                      image_counts=dict(Counter(item["image"] for item in plan)))
    output = (args.output_dir or Path("runs") / (run_id + ("-cleanup" if args.cleanup_run else ""))).resolve()
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "config.json", config)
    write_json(output / "plan.json", plan)
    print(f"Output: {output}", flush=True)
    print(json.dumps(config, ensure_ascii=False, indent=2), flush=True)
    if args.dry_run:
        return 0
    os.environ["E2B_API_URL"] = config["api_url"]
    os.environ["E2B_SANDBOX_URL"] = config["api_url"]
    os.environ.setdefault("E2B_API_KEY", "e2b_0000000000000000000000000000000000000000")
    os.environ.setdefault("E2B_ACCESS_TOKEN", "dummy")
    benchmark = Benchmark(config, output)
    loop = asyncio.get_running_loop()
    def stop():
        benchmark.stop = True
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop)
    # Preflight read: fail before creating anything if API/listing is unavailable.
    try:
        discovered = await benchmark.discover()
    except Exception:
        benchmark.journal.close()
        raise
    if args.cleanup_run:
        benchmark.live = discovered
        # Retain known IDs too, even if a concurrent inventory is incomplete.
        journal = args.cleanup_run / "operations.jsonl"
        if journal.exists():
            for line in journal.read_text(encoding="utf-8").splitlines():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get("phase") in ("create", "warmup_create") and row.get("sandbox_id"):
                    saved_item = {key: row[key] for key in ("index", "image", "sandbox_id")}
                    saved_item["round"] = row.get("round", 0 if row.get("index") == 0 else 1)
                    benchmark.live.setdefault(row["sandbox_id"], saved_item)
    summary = await benchmark.run(plan)
    print(f"Measured rounds: {summary['rounds_attempted']}/{summary['rounds_requested']}; "
          f"successful rounds: {summary['rounds_succeeded']}; overall averages exclude warmup.")
    for phase in ("create", "pause", "resume", "delete"):
        result = summary[phase]
        print(f"{phase} per-round batch completion: "
              f"mean={result['round_wall_mean_sec']} sec; "
              f"P50={result['round_wall_p50_sec']} sec; "
              f"P95={result['round_wall_p95_sec']} sec; "
              f"rounds={result['round_wall_samples']}; "
              f"excluded_rounds={result['round_wall_excluded']}")
        print(f"{phase} individual sandbox SDK call: "
              f"mean={result['mean_sec']} sec; "
              f"success={result['succeeded']} failure={result['failed']} "
              f"absent={result['already_absent']} already_paused={result['already_paused']}")
    print(f"Measured lifecycle wall: total={summary['measured_rounds_wall_total_sec']:.6f} sec; "
          f"mean_per_round={summary['measured_rounds_wall_mean_sec']} sec")
    print(f"Overall wall (includes warmup, reporting and cleanup/checks): {summary['elapsed_wall_sec']:.6f} sec")
    print(f"valid={summary['valid']}; remaining={len(summary['remaining_sandboxes'])}; report={output / 'summary.json'}")
    if args.cleanup_run:
        return 0 if not summary["remaining_sandboxes"] and not summary["errors"] else 1
    return 0 if summary["valid"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main_async(parse_args())))
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=__import__("sys").stderr)
        raise SystemExit(1)
