//! Library-only process transport. No CLI/env selection or persistence callbacks.
//! The trusted host supplies settings. Operator receiver environment is inherited
//! for capture; stripping credentials before writer launch belongs to integration.
use crate::{bounded_process, capture_bridge::*};
use std::{fmt, path::PathBuf, process::Command, time::Duration};

pub struct ProcessSinkSettings {
    executable: PathBuf,
    registry: PathBuf,
    state: PathBuf,
    timeout: Duration,
    response_cap: usize,
}
impl ProcessSinkSettings {
    pub fn new(
        executable: PathBuf,
        registry: PathBuf,
        state: PathBuf,
        timeout: Duration,
        response_cap: usize,
    ) -> Result<Self, Refused> {
        if [&executable, &registry, &state]
            .iter()
            .any(|p| !p.is_absolute())
            || timeout < Duration::from_millis(1)
            || timeout > Duration::from_millis(30000)
            || !(1..=MAX_WIRE_BYTES).contains(&response_cap)
        {
            return Err(Refused);
        }
        Ok(Self {
            executable,
            registry,
            state,
            timeout,
            response_cap,
        })
    }
}
pub struct ProcessSink {
    settings: ProcessSinkSettings,
}
impl ProcessSink {
    pub fn new(settings: ProcessSinkSettings) -> Self {
        Self { settings }
    }
    fn invoke(&self, operation: &str, input: &[u8]) -> Result<Vec<u8>, Refused> {
        if input.len() > MAX_WIRE_BYTES {
            return Err(Refused);
        }
        let s = &self.settings;
        let mut command = Command::new(&s.executable);
        command
            .arg("--config")
            .arg(&s.registry)
            .arg("capture")
            .arg(operation)
            .arg("--state-dir")
            .arg(&s.state)
            .arg("--json");
        let output = bounded_process::output_with_input_aggregate(
            &mut command,
            s.timeout,
            s.response_cap,
            input,
        )
        .map_err(|_| Refused)?;
        if !output.status.success() {
            return Err(Refused);
        }
        Ok(output.stdout)
    }
    pub fn begin(&self, request: &BeginRequest) -> Result<Prepared, Refused> {
        let input = request.encode()?;
        decode_begin(&self.invoke("begin", &input)?, request)
    }
    pub fn finish(
        &self,
        binding: &CaptureBinding,
        request: &FinishRequest,
    ) -> Result<LocalFrozen, Refused> {
        if &request.capture_id != binding.capture_id() {
            return Err(Refused);
        }
        let input = request.encode()?;
        decode_terminal(&self.invoke("finish", &input)?, binding)
    }
    pub fn retry(&self, binding: &CaptureBinding) -> Result<LocalFrozen, Refused> {
        let input = RetryRequest {
            capture_id: binding.capture_id().clone(),
        }
        .encode()?;
        decode_terminal(&self.invoke("retry", &input)?, binding)
    }
}
impl fmt::Debug for ProcessSinkSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessSinkSettings([REDACTED])")
    }
}
impl fmt::Debug for ProcessSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessSink([REDACTED])")
    }
}
