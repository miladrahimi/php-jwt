<?php

declare(strict_types=1);

// Fails the build when line (statement) coverage in a clover report drops
// below the given minimum percentage.
//
// Usage: php coverage-check.php <clover.xml> <minimum-percent>

if ($argc !== 3) {
    fwrite(STDERR, "Usage: php coverage-check.php <clover.xml> <minimum-percent>\n");
    exit(2);
}

[, $file, $minimum] = $argv;

if (!is_readable($file)) {
    fwrite(STDERR, "Cannot read clover report: $file\n");
    exit(2);
}

$metrics = (new SimpleXMLElement(file_get_contents($file)))->project->metrics;
$statements = (int) $metrics['statements'];
$covered = (int) $metrics['coveredstatements'];

if ($statements === 0) {
    fwrite(STDERR, "The clover report contains no statements.\n");
    exit(2);
}

$coverage = 100 * $covered / $statements;

printf("Line coverage: %.2f%% (%d/%d statements, minimum %s%%)\n", $coverage, $covered, $statements, $minimum);

exit($coverage >= (float) $minimum ? 0 : 1);
