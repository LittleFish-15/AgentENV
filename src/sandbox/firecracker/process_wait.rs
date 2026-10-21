//! Bound a forced reap without treating a deadline as confirmed process exit.
use std::future::Future;
use std::io;
use tokio::time::{timeout, Duration};

pub(super) async fn forced_reap<T>(
    deadline: Duration,
    wait: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    timeout(deadline, wait).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "forced Firecracker exit unconfirmed before reap deadline",
        )
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blocked_reap_is_an_error_not_a_confirmed_exit() {
        let result = forced_reap(
            Duration::from_millis(1),
            std::future::pending::<io::Result<()>>(),
        )
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn confirmed_exit_value_is_preserved() {
        assert_eq!(
            forced_reap(Duration::from_secs(1), async { Ok(73) })
                .await
                .unwrap(),
            73
        );
    }

    #[tokio::test]
    async fn reap_error_is_preserved() {
        let result = forced_reap(Duration::from_secs(1), async {
            Err::<(), _>(io::Error::from_raw_os_error(10))
        })
        .await;
        assert_eq!(result.unwrap_err().raw_os_error(), Some(10));
    }
}
