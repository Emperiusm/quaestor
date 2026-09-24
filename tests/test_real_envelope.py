"""The parser, tested against REAL Claude Code bytes -- not bytes this project generated.

THIS IS THE CONTROL THAT CLAUSE 2 OF THE INSTRUMENT DOCTRINE DEMANDS
--------------------------------------------------------------------
    "A control that consumes only your own output tests SERIALIZATION, not VERIFICATION.
     Feed it bytes you did not generate."

The source deployment paid for that sentence with ``test_a_changed_byte_is_detected``, which round-tripped a
manifest its own renderer wrote -- lowercase, no BOM, flat -- and therefore could not catch
uppercase hex, a BOM-led entry, or nested paths, all three of which were live in production.

``tests/fixtures/real_claude_stdout.json`` is the verbatim stdout of the P1 smoke's real
``claude -p`` child (CLI 2.1.185, subscription auth, Windows 11). Every assertion below is about
the INSTALLED BINARY's behaviour, and every one of them would have been a guess without it.

If this fixture is missing, the tests SKIP rather than pass -- an absent instrument is not a
clean reading. They refuse to skip under CI, where the verdict binds (doctrine clause 3).
"""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quaestor.core import handoff  # noqa: E402
from quaestor.core.executor_contract import (envelope_is_error, envelope_session_id,  # noqa: E402
                                   envelope_telemetry, extract_structured, handoff_strength,
                                   HANDOFF_STRENGTH_NATIVE, parse_envelope)
from quaestor.core.identity import RunBinding  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures",
                       "real_claude_stdout.json")


def _load_raw():
    with open(FIXTURE, "rb") as fh:
        return fh.read().decode("utf-8")


class TestRealClaudeEnvelope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(FIXTURE):
            if os.environ.get("CI"):
                raise AssertionError(
                    "the real-envelope fixture is absent and CI must not skip it: run "
                    "`python p1_smoke.py` to capture %s" % FIXTURE)
            raise unittest.SkipTest(
                "no real-envelope fixture yet; run `python p1_smoke.py` to capture one")
        cls.raw = _load_raw()

    def test_the_real_envelope_parses(self):
        env, note = parse_envelope(self.raw)
        self.assertIsNotNone(env, note)
        self.assertEqual(env.get("type"), "result")

    def test_structured_output_is_found_where_the_real_cli_puts_it(self):
        env, _ = parse_envelope(self.raw)
        payload, source, outcome = extract_structured(env)
        self.assertEqual(outcome, "FOUND")
        self.assertEqual(source, "structured_output",
                         "the installed CLI moved the structured result; the adapter's recorded "
                         "source string is how that becomes visible instead of silent")
        self.assertIsInstance(payload, dict)

    def test_the_real_fixture_yields_native_schema_validated_strength(self):
        """The installed CLI validated this payload against OUR json-schema (--json-schema).

        The durable record must say NATIVE for exactly this shape, so a schema-validated
        handoff can never be mistaken downstream for one recovered from prose.
        """
        env, _ = parse_envelope(self.raw)
        _, source, outcome = extract_structured(env)
        self.assertEqual(outcome, "FOUND")
        self.assertEqual(handoff_strength(source), HANDOFF_STRENGTH_NATIVE)

    def test_the_real_payload_satisfies_the_handoff_contract(self):
        env, _ = parse_envelope(self.raw)
        payload, _, _ = extract_structured(env)
        binding = RunBinding("(any)", payload["workflow_id"], payload["step_id"],
                             payload["run_nonce"])
        v = handoff.validate_handoff(payload, binding)
        self.assertTrue(v.valid, v.reason)

    def test_the_real_payload_is_refused_against_a_different_run(self):
        """The identity check must BITE on real bytes, not only on ours."""
        env, _ = parse_envelope(self.raw)
        payload, _, _ = extract_structured(env)
        foreign = RunBinding("other-run", payload["workflow_id"], payload["step_id"],
                             "a-different-nonce")
        v = handoff.validate_handoff(payload, foreign)
        self.assertEqual(v.outcome, handoff.RUN_IDENTITY_REFUSED)

    def test_the_model_returned_literal_json_booleans(self):
        """--json-schema produced real booleans, not the strings that would invert their meaning."""
        env, _ = parse_envelope(self.raw)
        payload, _, _ = extract_structured(env)
        for flag in ("authorized_scope_exhausted", "continuation_allowed",
                     "owner_decision_required"):
            self.assertIn(payload.get(flag), (True, False), flag)

    def test_session_id_is_captured_from_the_real_envelope(self):
        env, _ = parse_envelope(self.raw)
        sid = envelope_session_id(env)
        self.assertTrue(sid)
        self.assertEqual(len(sid), 36, "expected a UUID-shaped session id")

    def test_is_error_is_read_as_a_literal_boolean(self):
        env, _ = parse_envelope(self.raw)
        errored, subtype = envelope_is_error(env)
        self.assertFalse(errored)
        self.assertEqual(subtype, "success")

    def test_telemetry_extracts_the_fields_this_cli_actually_emits(self):
        env, _ = parse_envelope(self.raw)
        tel = envelope_telemetry(env)
        self.assertEqual(tel["stop_reason"], "end_turn")
        self.assertEqual(tel["terminal_reason"], "completed")
        self.assertEqual(tel["permission_denial_count"], 0,
                         "a read-only profile reading one file should trigger no denials")
        self.assertIsInstance(tel["num_turns"], int)
        self.assertIsNotNone(tel["models_reported"])

    def test_the_cost_field_is_recorded_but_never_interpreted(self):
        """The envelope reports a cost even on subscription auth. Record it; do not read it."""
        env, _ = parse_envelope(self.raw)
        tel = envelope_telemetry(env)
        self.assertIn("total_cost_usd_reported", tel)
        self.assertIn("not interpreted as a billed charge", tel["cost_note"].lower())
        # The figure travels verbatim; nothing derives a verdict from it.
        self.assertEqual(tel["total_cost_usd_reported"], json.loads(self.raw).get("total_cost_usd"))

    def test_a_truncated_real_envelope_is_refused_not_partially_believed(self):
        """Mutation on real bytes: cut the file in half and it must not yield a handoff."""
        env, err = parse_envelope(self.raw[: len(self.raw) // 2])
        self.assertIsNone(env)
        self.assertIn("not valid JSON", err)

    def test_a_real_envelope_stripped_of_its_structured_output_yields_nothing(self):
        doc = json.loads(self.raw)
        doc.pop("structured_output", None)
        payload, _, outcome = extract_structured(doc)
        self.assertIsNone(payload,
                          "the prose in `result` must not be mistaken for a structured handoff")
        self.assertEqual(outcome, "NO_STRUCTURED_OUTPUT")


CODEX_JSONL_FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures",
                                   "codex_exec_jsonl.jsonl")


class TestCodexJsonlEnvelope(unittest.TestCase):
    """The streamed-events shape (bd quaestor-lh0): ``codex exec --json`` emits JSONL events,
    not one document -- the gap quaestor-1ng flagged when the codex-cli executor became
    dispatchable.

    HONESTY ABOUT THE BYTES: ``codex_exec_jsonl.jsonl`` is CODEX-SHAPED after the CLI's
    documented event stream (thread/turn/item lifecycle), NOT a verbatim recording -- no codex
    binary was available on the recording box. It stands exactly where
    real_claude_stdout.json stood before p1_smoke.py captured real bytes: the PARSER rules are
    what these controls pin, and a verbatim recording should replace the fixture the first
    time a live codex run is captured. Every assertion here would survive that replacement's
    event vocabulary changing, because none of them parse event semantics beyond dict-ness.
    """

    @classmethod
    def setUpClass(cls):
        with open(CODEX_JSONL_FIXTURE, "rb") as fh:
            cls.raw = fh.read().decode("utf-8")

    def test_the_stream_yields_its_terminal_object_with_an_honest_note(self):
        env, note = parse_envelope(self.raw)
        self.assertIsNotNone(env, note)
        self.assertIsInstance(env, dict)
        # The LAST line, not the first: thread.started must lose to turn.completed.
        self.assertEqual(env.get("type"), "turn.completed")
        self.assertIn("JSONL", note)
        self.assertIn("last of 6 objects", note)

    def test_the_whole_document_rule_still_wins_when_it_parses(self):
        env, note = parse_envelope(self.raw.splitlines()[0])
        self.assertEqual(note, "")
        self.assertEqual(env.get("type"), "thread.started")

    def test_a_torn_trailing_line_is_skipped_and_counted_not_believed(self):
        torn = self.raw + '{"type":"turn.completed","usage":{"input_tok'
        env, note = parse_envelope(torn)
        self.assertIsNotNone(env, note)
        self.assertEqual(env.get("type"), "turn.completed",
                         "the torn tail must not displace the last COMPLETE object")
        self.assertIn("1 non-object/incomplete line(s) skipped", note)

    def test_non_object_lines_are_skipped_and_counted(self):
        stream = '"a bare string"\n42\n{"type":"item.started"}\n'
        env, note = parse_envelope(stream)
        self.assertEqual(env.get("type"), "item.started")
        self.assertIn("2 non-object/incomplete line(s) skipped", note)

    def test_garbage_is_refused_with_the_same_refusal_vocabulary(self):
        env, err = parse_envelope("not json at all\nreally not\n")
        self.assertIsNone(env)
        self.assertIn("not valid JSON", err)

    def test_an_array_of_objects_keeps_its_own_note(self):
        doc = [{"type": "a"}, {"type": "b"}]
        raw = json.dumps(doc)
        env, note = parse_envelope(raw)
        self.assertEqual(env.get("type"), "b")
        self.assertEqual(note, "envelope was an array; used the last object")

    def test_structured_output_in_the_terminal_object_flows_to_extraction(self):
        """The adapter contract for a native-structured codex mode: whatever the stream shape,
        extraction reads the object parse_envelope chose -- never earlier events."""
        payload = {"workflow_id": "wf", "step_id": "s1", "run_nonce": "n", "protocol": "p",
                   "protocol_version": 1}
        stream = '{"type":"turn.started"}\n%s\n' % json.dumps(
            {"type": "turn.completed", "structured_output": payload})
        env, _note = parse_envelope(stream)
        found, source, outcome = extract_structured(env)
        self.assertEqual(outcome, "FOUND")
        self.assertEqual(source, "structured_output")
        self.assertEqual(found["run_nonce"], "n")


if __name__ == "__main__":
    unittest.main()
