package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type Row struct {
	Index     int     `json:"index"`
	Round     int     `json:"round"`
	Batch     int     `json:"batch"`
	Phase     string  `json:"phase"`
	ID        string  `json:"sandbox_id"`
	Elapsed   float64 `json:"elapsed_sec"`
	Header    float64 `json:"header_sec"`
	Started   string  `json:"started_at"`
	Completed string  `json:"completed_at"`
	Status    string  `json:"status"`
	Error     string  `json:"error"`
}

func write(path string, v interface{}) {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		panic(e)
	}
}
func statistics(rows []Row, phase string, wall float64) map[string]interface{} {
	v := []float64{}
	errors := 0
	for _, r := range rows {
		if r.Round <= 0 || r.Phase != phase {
			continue
		}
		if r.Status == "ok" {
			v = append(v, r.Elapsed)
		} else {
			errors++
		}
	}
	sort.Float64s(v)
	out := map[string]interface{}{"succeeded": len(v), "failed": errors, "wall_total_sec": wall}
	if len(v) == 0 {
		return out
	}
	sum := 0.
	for _, x := range v {
		sum += x
	}
	median := v[len(v)/2]
	if len(v)%2 == 0 {
		median = (v[len(v)/2-1] + median) / 2
	}
	out["mean_sec"] = sum / float64(len(v))
	out["p50_sec"] = median
	out["p95_sec"] = v[int(math.Ceil(float64(len(v))*.95))-1]
	out["max_sec"] = v[len(v)-1]
	return out
}
func monoNS() int64 {
	var ts syscall.Timespec
	_, _, e := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1, uintptr(unsafe.Pointer(&ts)), 0)
	if e != 0 {
		panic(e)
	}
	return ts.Sec*1000000000 + ts.Nsec
}
func main() {
	d := flag.String("output", "", "existing trial dir")
	tpl := flag.String("template", "", "template")
	tag := flag.String("run-id", "", "run metadata")
	rounds := flag.Int("rounds", 1, "formal lifecycle rounds")
	barrier := flag.Bool("barrier", true, "wait for controller after warmup")
	flag.Parse()
	if os.Geteuid() != 1002 || *d == "" || *tag == "" {
		panic("args/uid")
	}
	result := filepath.Join(*d, "result")
	if e := os.Mkdir(result, 0700); e != nil {
		panic(e)
	}
	api, key := os.Getenv("E2B_API_URL"), os.Getenv("E2B_API_KEY")
	if api == "" || key == "" {
		panic("API env")
	}
	client := &http.Client{Transport: &http.Transport{MaxIdleConns: 120, MaxIdleConnsPerHost: 120, MaxConnsPerHost: 120, IdleConnTimeout: 90 * time.Second}, Timeout: 600 * time.Second}
	defer client.CloseIdleConnections()
	ids := make([]string, 101)
	rows := []Row{}
	var mu sync.Mutex
	walls := map[string]float64{}
	roundResults := []map[string]interface{}{}
	windows := []map[string]interface{}{}
	journal, e := os.OpenFile(filepath.Join(result, "operations.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		panic(e)
	}
	defer journal.Close()
	operation := func(phase string, index, round int) Row {
		r := Row{Index: index, Round: round, Batch: 1, Phase: phase, ID: ids[index], Status: "error"}
		method, url := http.MethodPost, api+"/sandboxes"
		var body interface{}
		switch phase {
		case "create":
			body = map[string]interface{}{"templateID": *tpl, "timeout": 86400, "secure": true, "allow_internet_access": true, "envVars": map[string]string{}, "metadata": map[string]string{"lifecycle_benchmark_run": *tag, "lifecycle_benchmark_index": fmt.Sprint(index), "lifecycle_benchmark_round": fmt.Sprint(round)}}
		case "pause":
			url += "/" + r.ID + "/pause"
			body = map[string]bool{"memory": true}
		case "resume":
			url += "/" + r.ID + "/connect"
			body = map[string]int{"timeout": 86400}
		case "delete":
			method = http.MethodDelete
			url += "/" + r.ID
		}
		r.Started = time.Now().UTC().Format(time.RFC3339Nano)
		start := time.Now()
		var raw []byte
		if body != nil {
			var marshalErr error
			raw, marshalErr = json.Marshal(body)
			if marshalErr != nil {
				panic(marshalErr)
			}
		}
		req, er := http.NewRequest(method, url, bytes.NewReader(raw))
		if er != nil {
			r.Error = er.Error()
		} else {
			req.Header.Set("X-API-Key", key)
			if body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, er := client.Do(req)
			r.Header = time.Since(start).Seconds()
			if er != nil {
				r.Error = er.Error()
			} else {
				b, er := io.ReadAll(resp.Body)
				if er != nil {
					r.Error = er.Error()
				} else {
					ok := resp.StatusCode >= 200 && resp.StatusCode < 300
					if phase == "resume" {
						ok = resp.StatusCode == 201
					}
					if !ok {
						r.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
					} else if phase == "create" || phase == "resume" {
						var v struct {
							ID string `json:"sandboxID"`
						}
						if er = json.Unmarshal(b, &v); er != nil {
							r.Error = er.Error()
						} else if v.ID == "" || (phase == "resume" && v.ID != r.ID) {
							r.Error = "sandboxID mismatch"
						} else {
							r.ID = v.ID
							ids[index] = v.ID
							r.Status = "ok"
						}
					} else {
						r.Status = "ok"
						if phase == "delete" {
							ids[index] = ""
						}
					}
				}
				resp.Body.Close()
			}
		}
		r.Elapsed = time.Since(start).Seconds()
		r.Completed = time.Now().UTC().Format(time.RFC3339Nano)
		mu.Lock()
		rows = append(rows, r)
		mu.Unlock()
		return r
	}
	flushed := 0
	flush := func() {
		for _, r := range rows[flushed:] {
			if err := json.NewEncoder(journal).Encode(r); err != nil {
				panic(err)
			}
		}
		flushed = len(rows)
	}
	success := true
	for _, phase := range []string{"create", "pause", "resume", "delete"} {
		if operation(phase, 0, 0).Status != "ok" {
			success = false
			break
		}
	}
	flush()
	if success && *barrier {
		write(filepath.Join(*d, "warmup-ready.json"), map[string]interface{}{"run_id": *tag, "status": "warmup-complete"})
		deadline := time.Now().Add(120 * time.Second)
		for {
			if _, e := os.Stat(filepath.Join(*d, "CONTINUE")); e == nil {
				break
			}
			if _, e := os.Stat(filepath.Join(*d, "STOP")); e == nil || time.Now().After(deadline) {
				success = false
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	if success {
		for round := 1; round <= *rounds && success; round++ {
			offset := len(rows)
			rw := map[string]float64{}
			for _, phase := range []string{"create", "pause", "resume", "delete"} {
				diagnosticBarrier(*d, phase, "before", ids)
				startNS := monoNS()
				start := time.Now()
				var wg sync.WaitGroup
				var fail bool
				var fm sync.Mutex
				for i := 1; i <= 100; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						if operation(phase, i, round).Status != "ok" {
							fm.Lock()
							fail = true
							fm.Unlock()
						}
					}(i)
				}
				wg.Wait()
				wall := time.Since(start).Seconds()
				endNS := monoNS()
				walls[phase] += wall
				rw[phase] = wall
				windows = append(windows, map[string]interface{}{"round": round, "phase": phase, "batch": 1, "start_ns": startNS, "end_ns": endNS, "wall_sec": wall, "clock": "CLOCK_MONOTONIC"})
				write(filepath.Join(result, "phase-windows.json"), windows)
				flush()
				diagnosticBarrier(*d, phase, "after", ids)
				if fail {
					success = false
					break
				}
			}
			rs := map[string]interface{}{"round": round, "valid": success}
			for _, phase := range []string{"create", "pause", "resume", "delete"} {
				x := statistics(rows[offset:], phase, rw[phase])
				x["wall_sec"] = rw[phase]
				rs[phase] = x
			}
			roundResults = append(roundResults, rs)
		}
	}
	// Best-effort only our confirmed IDs; controller separately discovers run-tagged lost responses.
	if !success {
		for i, id := range ids {
			if id != "" {
				operation("delete", i, -1)
			}
		}
	}
	flush()
	remaining := []string{}
	for _, id := range ids {
		if id != "" {
			remaining = append(remaining, id)
		}
	}
	summary := map[string]interface{}{"valid": success && len(remaining) == 0, "remaining_sandboxes": remaining, "run_id": *tag, "client": "go", "config": map[string]interface{}{"total": 100, "rounds": *rounds, "batch_size": 100, "warmup_count": 1}}
	for _, p := range []string{"create", "pause", "resume", "delete"} {
		x := statistics(rows, p, walls[p])
		x["wall_mean_per_round_sec"] = walls[p] / float64(*rounds)
		summary[p] = x
	}
	summary["rounds"] = roundResults
	summary["rounds_succeeded"] = len(roundResults)
	write(filepath.Join(result, "summary.json"), summary)
	if !success {
		os.Exit(1)
	}
}

func diagnosticBarrier(dir, phase, edge string, ids []string) {
	path := os.Getenv("LIFECYCLE_BOUNDARY_DIR")
	if path == "" {
		return
	}
	selected := []string{}
	for _, id := range ids {
		if id != "" {
			selected = append(selected, id)
		}
	}
	p := filepath.Join(path, phase+"-"+edge+".json")
	write(p, map[string]interface{}{"phase": phase, "edge": edge, "sandboxIds": selected})
	end := time.Now().Add(120 * time.Second)
	for {
		if b, e := os.ReadFile(p + ".ack"); e == nil {
			if string(b) != "ok" {
				panic("observer rejected boundary")
			}
			break
		}
		if time.Now().After(end) {
			panic("observer barrier timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
