package server

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// migrateWatchdogSettings performs the one-time v1 upgrade that removes the
// duplicate cycle settings. The unique source of truth after this runs is the
// Worker Agent's run_seconds; the legacy worker_run_seconds / watchdog_cycle_after_sec
// keys are read once and deleted.
//
// Historical values override the Agent only when they carry a positive cycle.
// With no override the Agent's current run_seconds is preserved, including 0 and
// values below the Slow Path. A historical override that cannot satisfy the
// ordering rule aborts the migration instead of silently rewriting it. All
// writes, deletes and the completion marker commit together.
func (s *Server) migrateWatchdogSettings() error {
	if s == nil || s.m == nil || s.m.pg == nil {
		return nil
	}
	pg := s.m.pg
	if v, ok, err := pg.GetSetting(settingWatchdogMigrated); err != nil {
		return fmt.Errorf("读取配置迁移标记: %w", err)
	} else if ok && (v == "true" || v == "1") {
		return nil
	}

	legacyWorker, workerSet, err := optionalSettingInt(pg, legacySettingWorkerRunSeconds)
	if err != nil {
		return err
	}
	legacyCycle, cycleSet, err := optionalSettingInt(pg, legacySettingWatchdogCycleSec)
	if err != nil {
		return err
	}
	worker, err := pg.GetAgentByKey("worker")
	if err != nil {
		return fmt.Errorf("读取 Worker Agent: %w", err)
	}
	if worker == nil {
		return fmt.Errorf("Worker Agent 不存在，无法完成看护配置迁移")
	}
	var override *int
	source := "worker.run_seconds"
	switch {
	case workerSet && legacyWorker > 0:
		override = new(legacyWorker)
		source = legacySettingWorkerRunSeconds
	case cycleSet && legacyCycle > 0:
		override = new(legacyCycle)
		source = legacySettingWatchdogCycleSec
	}
	if override != nil {
		pressure, err := settingIntForMigration(pg, settingWatchdogPressureSec, defaultWatchdogPressureSec)
		if err != nil {
			return err
		}
		slow, err := settingIntForMigration(pg, settingWatchdogSlowPathSec, defaultWatchdogSlowPathSec)
		if err != nil {
			return err
		}
		if !(pressure > 0 && pressure < slow && slow < *override) {
			return fmt.Errorf("历史配置迁移后的周期 %d 秒不满足压力提示 < Slow Path < 周期（当前 %d / %d），请先修正历史设置",
				*override, pressure, slow)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pg.ApplyWatchdogSettingsMigration(ctx, override,
		[]string{legacySettingWorkerRunSeconds, legacySettingWatchdogCycleSec},
		settingWatchdogMigrated, "true"); err != nil {
		return fmt.Errorf("应用看护配置迁移: %w", err)
	}
	effective := worker.RunSecs
	if override != nil {
		effective = *override
	}
	log.Printf("[watchdog] 配置迁移完成：Worker 周期 %ds（来源 %s）", effective, source)
	return nil
}

// optionalSettingInt reads an integer setting without applying a default, so a
// legacy explicit 0 can be distinguished from an absent key. Parse errors are
// returned instead of being treated as an absent value.
func optionalSettingInt(pg *db.DB, key string) (int, bool, error) {
	v, ok, err := pg.GetSetting(key)
	if err != nil {
		return 0, false, fmt.Errorf("读取历史设置 %s: %w", key, err)
	}
	if !ok {
		return 0, false, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false, fmt.Errorf("历史设置 %s 不是整数: %q", key, v)
	}
	return n, true, nil
}

// settingIntForMigration reads a positive integer setting with a default only
// when the key is absent. Invalid stored values abort the migration.
func settingIntForMigration(pg *db.DB, key string, def int) (int, error) {
	v, ok, err := pg.GetSetting(key)
	if err != nil {
		return 0, fmt.Errorf("读取看护设置 %s: %w", key, err)
	}
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("看护设置 %s 必须是大于 0 的整数，当前为 %q", key, v)
	}
	return n, nil
}
