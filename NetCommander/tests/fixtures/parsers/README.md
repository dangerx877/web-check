# Parser fixtures

Each `<parser_key>__<case>.txt` is raw CLI output; `<same name>.expected.json` is the parsed result.

**Provenance - please read:** these samples are *synthetic*: hand-written to follow each vendor's documented
output layout, then the parser's current output was frozen as the expectation (golden / regression files).
They are **not captures from real devices** and the `.expected.json` files were not independently verified
against a device. They protect against accidental behaviour changes, not against format drift on real firmware.

## Contributing a real capture
1. Capture the command output from a real device (`show lldp neighbors detail`, ...). **Scrub** hostnames,
   IPs, MACs, serials and anything identifying; check no secrets are present.
2. Save it as `tests/fixtures/parsers/<parser_key>__<short_case>.txt` (keys: see `netcommander.parsers.RAW_PARSERS`).
3. Write the `.expected.json` by hand from what the device output actually says (do not just paste parser output).
4. Run `pytest tests/test_parser_fixtures.py`; if the parser disagrees with your hand-written expectation, you found a bug.
