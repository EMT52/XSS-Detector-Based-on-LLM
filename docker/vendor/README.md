This directory is reserved for the real instrumented PHP 7.0 source archive.

An optional `downloads/` directory may contain the six files named in
`docker/sources.lock.json`. Local builds reuse them only after SHA256 validation.
These cache files are ignored by Git and excluded from the source exporter;
they are used only in the build stage and are not copied into the runtime image.

The original `llm-xss/php-instr.tar.gz` is a Software Heritage omission notice,
not a source archive. The default image uses ordinary PHP 7.0.33 and does not
reproduce sanitizer feedback instrumentation.

To build an instrumented variant, place the genuine archive here as
`php-instrumented.tar.gz` (one enclosing source directory), inspect its contents,
then run `PHP_FLAVOR=instrumented docker compose build`. The archive is ignored
by Git. This variant must be verified against its expected feedback output
before reporting full paper reproduction; the flavor name only records which
source was supplied.
