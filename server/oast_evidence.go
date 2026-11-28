package server

import (
	"context"
	"fmt"

	"github.com/Autumn-27/artex/agent"
)

// validateOASTEvidence decides whether an `oast:<id>` reference may be used as
// evidence for the calling run. Two things must hold, and the second is the one
// the previous implementation missed:
//
//  1. the interaction exists — in the live ring, or in the durable table when the
//     callback is older than this process;
//  2. it belongs to THIS task. A callback issued by another task proves that
//     task's target was reachable, not this one's; accepting it would let a worker
//     borrow a neighbour's evidence to prove its own blind vulnerability.
//
// An untracked callback (a hit on a path whose token was never issued) is
// rejected outright: with no issuing run there is nothing to attribute it to.
func (m *Manager) validateOASTEvidence(ctx context.Context, rawID string) error {
	taskID := agent.RunInfoFrom(ctx).TaskID
	osrv := m.OAST()

	if osrv != nil {
		if ev, ok := osrv.Lookup(parseID(rawID)); ok {
			if ev.TaskID <= 0 {
				return fmt.Errorf("带外回调证据 oast:%s 无法归属到任何任务（token 未被本平台签发），不能作为漏洞证据", rawID)
			}
			if taskID > 0 && ev.TaskID != taskID {
				return fmt.Errorf("带外回调证据 oast:%s 属于其他任务（task %d），不能用于证明本任务的漏洞", rawID, ev.TaskID)
			}
			return nil
		}
	}

	// Not in the live ring: a callback recorded before a restart. The durable row
	// is the authoritative attribution in that case.
	if m.pg == nil {
		return fmt.Errorf("带外回调证据 oast:%s 不存在；请先 oast_poll 确认命中", rawID)
	}
	owner, found, err := m.pg.OASTInteractionTask(parseID(rawID))
	if err != nil {
		return fmt.Errorf("校验带外回调证据 oast:%s 归属失败: %w", rawID, err)
	}
	if !found {
		return fmt.Errorf("带外回调证据 oast:%s 不存在（内存与持久记录都没有）；请先 oast_poll 确认命中", rawID)
	}
	if owner <= 0 {
		return fmt.Errorf("带外回调证据 oast:%s 无法归属到任何任务，不能作为漏洞证据", rawID)
	}
	if taskID > 0 && owner != taskID {
		return fmt.Errorf("带外回调证据 oast:%s 属于其他任务（task %d），不能用于证明本任务的漏洞", rawID, owner)
	}
	return nil
}

func parseID(raw string) int64 {
	var n int64
	if _, err := fmt.Sscan(raw, &n); err != nil {
		return 0
	}
	return n
}
