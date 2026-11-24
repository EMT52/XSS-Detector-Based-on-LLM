<?php

function send($value) { return 'global-send'; }

class UploadHandler {
    final public function header($str) {
        // $this->query() UploadHandler::send() pretend_call()
        $literal = '$this->query() UploadHandler::send() pretend_call()';
        $double = "UploadHandler::send() pretend_call()";
        $heredoc = <<<'TEXT'
$this->query() UploadHandler::send() pretend_call()
TEXT;
        header($str);
        HeAdEr($str);
        return $this /* receiver comment */ ->QuErY() . self::sEnD('') . self::formatLabel('');
    } // $this->query()

    final public static function send($value) { return 'static'; }
    private static function formatLabel($value) { return 'deeper definition'; }

    public function input($other) {
        return $other->sEND('unresolved-send') . $other->HeAdEr('unresolved-header');
    }

    public function query() { return 'instance'; } } function query() { return 'global'; }

class Other {
    public function query() { return 'other'; }
    public static function send($value) { return 'other-send'; }
}

echo (new UploadHandler())->HeAdEr('X-Fixture: neutral');
echo QuErY();
echo (new UPLOADHANDLER())->qUeRy();
echo uPloAdHaNdlEr::sEnD('');
echo sEnD('');
echo (new UploadHandler())->iNpuT(null);

('ready' == 'ready') && (1 > 0);
