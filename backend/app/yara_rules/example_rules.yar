/* Example YARA rule file for the Sentinel subset engine.
   Place .yar/.yara files in this directory to enable payload scanning. */

rule webshell_php_payload : webshell {
  meta:
    description = "Detects common PHP webshell invocation strings in payloads"
    severity = "critical"
    category = "webshell"

  strings:
    $a = "eval(" ascii nocase
    $b = "base64_decode" ascii nocase
    $c = "shell_exec" ascii nocase
    $d = "system(" ascii nocase

  condition:
    2 of them
}

rule metachar_injection : command_injection {
  meta:
    description = "Detects command chaining and substitution metacharacters"
    severity = "high"
    category = "command_injection"

  strings:
    $a = "; ls"
    $b = "; cat /etc/passwd"
    $c = "$("
    $d = "`" nocase

  condition:
    any of them
}

rule pe_mz_loader : executable {
  meta:
    description = "Detects MZ/PE header followed by an MS-DOS stub in a payload"
    severity = "medium"
    category = "executable_payload"

  strings:
    $mz = { 4D 5A [2-4096] 50 45 00 00 }

  condition:
    $mz
}
