package audit

import (
	"context"
	"encoding/json"
	"fmt"
)

// CompleteRuntimeInspection merges safe adapter metadata without replacing
// the operation identity. Retries cannot erase a completed check with an error.
func (s *Store) CompleteRuntimeInspection(id int64, outcome, severity string, confidence float64, attrs map[string]any) error {
	b, err := json.Marshal(attrs)
	if err != nil {
		return err
	}
	result, err := s.execDB(context.Background(), "runtime_inspection_complete", `UPDATE behavior_events
SET outcome = ?, severity = ?, confidence = ?,
attributes_json = json_patch(COALESCE(NULLIF(attributes_json, ''), '{}'), ?)
WHERE id = ? AND COALESCE(json_extract(attributes_json, '$.inspection_status'), '') != 'complete'`, outcome, severity, confidence, string(b), id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		_, ok, err := s.GetRuntimeEvent(id)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("runtime event %d unavailable", id)
		}
	}
	return nil
}

func (s *Store) MarkRuntimeInspectionEvaluated(id int64) error {
	_, err := s.execDB(context.Background(), "runtime_inspection_evaluated", `UPDATE behavior_events SET
attributes_json = json_set(COALESCE(NULLIF(attributes_json, ''), '{}'), '$.inspection_evaluated', json('true')) WHERE id = ?`, id)
	return err
}

func (s *Store) RuntimeEventByIngestKey(key string) (BehaviorEvent, bool, error) {
	var id int64
	err := s.db.QueryRowContext(context.Background(), `SELECT id FROM behavior_events WHERE ingest_key = ?`, key).Scan(&id)
	if err != nil {
		return BehaviorEvent{}, false, err
	}
	return s.GetRuntimeEvent(id)
}

// ConfirmInspectionBlocked is called only after an authenticated proxy reports
// that request forwarding or response delivery was actually refused.
func (s *Store) ConfirmInspectionBlocked(id int64) error {
	if _, err := s.execDB(context.Background(), "runtime_inspection_blocked", `UPDATE behavior_events SET outcome='blocked'
WHERE id=? AND json_extract(attributes_json,'$.inspection_status')='complete'`, id); err != nil {
		return err
	}
	if _, err := s.execDB(context.Background(), "runtime_detection_block_confirmed", `UPDATE runtime_detections SET status='mitigated'
WHERE "delete"=0 AND EXISTS (SELECT 1 FROM runtime_detection_events e WHERE e.detection_id=runtime_detections.detection_id AND e.event_id=?)
AND NOT EXISTS (SELECT 1 FROM runtime_detection_events e JOIN behavior_events b ON b.id=e.event_id WHERE e.detection_id=runtime_detections.detection_id AND b.outcome!='blocked')`, id); err != nil {
		return err
	}
	_, err := s.execDB(context.Background(), "runtime_response_block_confirmed", `UPDATE runtime_response_actions SET status='executed', result='proxy confirmed request forwarding or response delivery was blocked'
WHERE executor='inspect' AND decision_id IN (SELECT d.decision_id FROM runtime_decisions d JOIN runtime_detection_events e ON e.detection_id=d.detection_id WHERE e.event_id=?)`, id)
	return err
}
