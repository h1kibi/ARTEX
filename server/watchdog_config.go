package server

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Watchdog 的运行时配置全部来自 settings 键值表。阶段 0 到阶段 6 的生产默认
// 是关闭；自动化测试和后续验收通过修改这些键打开，代码路径本身不区分环境。
const (
	settingWatchdogEnabled     = "watchdog_enabled"
	settingWatchdogPressureSec = "watchdog_pressure_after_sec"
	settingWatchdogSlowPathSec = "watchdog_slow_path_after_sec"
	settingWatchdogCycleSec    = "watchdog_cycle_after_sec"
	settingWatchdogAgentKey    = "watchdog_agent_key"
	settingWatchdogAgentRetry  = "watchdog_agent_retry_sec"
	settingWorkerRunSeconds    = "worker_run_seconds"

	defaultWatchdogPressureSec = 480  // 8 分钟：压力提示
	defaultWatchdogSlowPathSec = 600  // 10 分钟：Slow Path 判断
	defaultWatchdogCycleSec    = 1200 // 20 分钟：周期处理
	defaultWatchdogAgentKey    = "watchdog"
	defaultWatchdogAgentRetry  = 300 // 5 分钟：Watchdog Agent 不可用后的重试间隔
)

type watchdogConfig struct {
	Enabled          bool
	PressureAfter    time.Duration
	SlowPathAfter    time.Duration
	CycleAfter       time.Duration
	AgentKey         string
	AgentRetry       time.Duration
	WorkerRunSeconds int
}

// watchdogWorkerRunSeconds resolves the effective Worker single-run limit.
// An explicit worker_run_seconds wins. With Watchdog enabled, 0 means
// unlimited: the user may keep approving C4, C5, … and a fixed multiple of
// the cycle would cut a legitimately continued run. The task deadline (if any)
// still clamps the run; Watchdog itself remains the termination mechanism.
func watchdogWorkerRunSeconds(base int, cfg watchdogConfig) int {
	if cfg.WorkerRunSeconds > 0 {
		return cfg.WorkerRunSeconds
	}
	if cfg.Enabled {
		return 0
	}
	return base
}

// settingsInt reads a positive integer setting, falling back to def when the
// key is absent or malformed. Settings are validated on write; this tolerant
// read keeps a hand-edited/legacy row from disabling the whole watchdog.
func settingsInt(pg *db.DB, key string, def int) int {
	if pg == nil {
		return def
	}
	v, ok, err := pg.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// watchdogConfig reads the effective configuration. The default is disabled, so
// every caller can run the same code path in development and production.
func (s *Server) watchdogConfig() watchdogConfig {
	cfg := watchdogConfig{
		PressureAfter: time.Duration(defaultWatchdogPressureSec) * time.Second,
		SlowPathAfter: time.Duration(defaultWatchdogSlowPathSec) * time.Second,
		CycleAfter:    time.Duration(defaultWatchdogCycleSec) * time.Second,
		AgentKey:      defaultWatchdogAgentKey,
		AgentRetry:    time.Duration(defaultWatchdogAgentRetry) * time.Second,
	}
	if s == nil || s.m == nil || s.m.pg == nil {
		return cfg
	}
	pg := s.m.pg
	cfg.Enabled = pg.GetBool(settingWatchdogEnabled, false)
	cfg.PressureAfter = time.Duration(settingsInt(pg, settingWatchdogPressureSec, defaultWatchdogPressureSec)) * time.Second
	cfg.SlowPathAfter = time.Duration(settingsInt(pg, settingWatchdogSlowPathSec, defaultWatchdogSlowPathSec)) * time.Second
	cfg.CycleAfter = time.Duration(settingsInt(pg, settingWatchdogCycleSec, defaultWatchdogCycleSec)) * time.Second
	cfg.AgentRetry = time.Duration(settingsInt(pg, settingWatchdogAgentRetry, defaultWatchdogAgentRetry)) * time.Second
	if v, ok, err := pg.GetSetting(settingWatchdogAgentKey); err == nil && ok && strings.TrimSpace(v) != "" {
		cfg.AgentKey = strings.TrimSpace(v)
	}
	if v, ok, err := pg.GetSetting(settingWorkerRunSeconds); err == nil && ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
			cfg.WorkerRunSeconds = n
		}
	}
	// 三个阈值必须严格递增；手工改坏的库回落默认值，避免 20 分钟检查在 10
	// 分钟之前反复触发。
	if !(cfg.PressureAfter < cfg.SlowPathAfter && cfg.SlowPathAfter < cfg.CycleAfter) {
		cfg.PressureAfter = time.Duration(defaultWatchdogPressureSec) * time.Second
		cfg.SlowPathAfter = time.Duration(defaultWatchdogSlowPathSec) * time.Second
		cfg.CycleAfter = time.Duration(defaultWatchdogCycleSec) * time.Second
	}
	return cfg
}

// watchdogSettingsPayload returns the persisted settings in the shape the
// settings page edits. Durations are exposed in seconds, matching the keys.
func (s *Server) watchdogSettingsPayload() map[string]any {
	cfg := s.watchdogConfig()
	return map[string]any{
		"watchdog_enabled":             cfg.Enabled,
		"watchdog_pressure_after_sec":  int(cfg.PressureAfter / time.Second),
		"watchdog_slow_path_after_sec": int(cfg.SlowPathAfter / time.Second),
		"watchdog_cycle_after_sec":     int(cfg.CycleAfter / time.Second),
		"watchdog_agent_key":           cfg.AgentKey,
		"watchdog_agent_retry_sec":     int(cfg.AgentRetry / time.Second),
		"worker_run_seconds":           cfg.WorkerRunSeconds,
	}
}

// watchdogSettingsPatch is the partial PUT body for the watchdog settings.
type watchdogSettingsPatch struct {
	Enabled     *bool   `json:"watchdog_enabled"`
	PressureSec *int    `json:"watchdog_pressure_after_sec"`
	SlowPathSec *int    `json:"watchdog_slow_path_after_sec"`
	CycleSec    *int    `json:"watchdog_cycle_after_sec"`
	AgentKey    *string `json:"watchdog_agent_key"`
	AgentRetry  *int    `json:"watchdog_agent_retry_sec"`
	WorkerRun   *int    `json:"worker_run_seconds"`
}

// applyWatchdogSettings validates the merged view once, then writes only the
// fields the caller sent. A partial PUT must not reset unrelated thresholds.
func (s *Server) applyWatchdogSettings(p watchdogSettingsPatch) error {
	cfg := s.watchdogConfig()
	if p.PressureSec != nil {
		cfg.PressureAfter = time.Duration(*p.PressureSec) * time.Second
	}
	if p.SlowPathSec != nil {
		cfg.SlowPathAfter = time.Duration(*p.SlowPathSec) * time.Second
	}
	if p.CycleSec != nil {
		cfg.CycleAfter = time.Duration(*p.CycleSec) * time.Second
	}
	if p.AgentKey != nil {
		cfg.AgentKey = strings.TrimSpace(*p.AgentKey)
	}
	if p.AgentRetry != nil {
		cfg.AgentRetry = time.Duration(*p.AgentRetry) * time.Second
	}
	if p.WorkerRun != nil {
		cfg.WorkerRunSeconds = *p.WorkerRun
	}
	if cfg.PressureAfter <= 0 || cfg.SlowPathAfter <= 0 || cfg.CycleAfter <= 0 {
		return fmt.Errorf("看护阈值必须大于 0 秒")
	}
	if !(cfg.PressureAfter < cfg.SlowPathAfter && cfg.SlowPathAfter < cfg.CycleAfter) {
		return fmt.Errorf("看护阈值必须满足：压力提示 < 慢速判断 < 周期处理")
	}
	if cfg.AgentRetry <= 0 {
		return fmt.Errorf("Watchdog Agent 重试间隔必须大于 0 秒")
	}
	if !reAgentKey.MatchString(cfg.AgentKey) {
		return fmt.Errorf("Watchdog Agent key 必须是小写字母开头，仅含小写字母、数字和下划线")
	}
	if cfg.WorkerRunSeconds < 0 {
		return fmt.Errorf("worker_run_seconds 不能为负数")
	}
	pg := s.m.pg
	if p.PressureSec != nil {
		if err := pg.SetSetting(settingWatchdogPressureSec, strconv.Itoa(*p.PressureSec)); err != nil {
			return err
		}
	}
	if p.SlowPathSec != nil {
		if err := pg.SetSetting(settingWatchdogSlowPathSec, strconv.Itoa(*p.SlowPathSec)); err != nil {
			return err
		}
	}
	if p.CycleSec != nil {
		if err := pg.SetSetting(settingWatchdogCycleSec, strconv.Itoa(*p.CycleSec)); err != nil {
			return err
		}
	}
	if p.AgentKey != nil {
		if err := pg.SetSetting(settingWatchdogAgentKey, cfg.AgentKey); err != nil {
			return err
		}
	}
	if p.AgentRetry != nil {
		if err := pg.SetSetting(settingWatchdogAgentRetry, strconv.Itoa(*p.AgentRetry)); err != nil {
			return err
		}
	}
	if p.WorkerRun != nil {
		if err := pg.SetSetting(settingWorkerRunSeconds, strconv.Itoa(*p.WorkerRun)); err != nil {
			return err
		}
	}
	if p.Enabled != nil {
		if err := pg.SetBool(settingWatchdogEnabled, *p.Enabled); err != nil {
			return err
		}
	}
	return nil
}
