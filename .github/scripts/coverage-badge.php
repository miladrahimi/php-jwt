<?php

declare(strict_types=1);

// Renders line (statement) coverage from a clover report as a shields.io
// endpoint-format JSON file (https://shields.io/badges/endpoint-badge).
//
// Usage: php coverage-badge.php <clover.xml> <output.json>

if ($argc !== 3) {
    fwrite(STDERR, "Usage: php coverage-badge.php <clover.xml> <output.json>\n");
    exit(2);
}

[, $file, $output] = $argv;

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
$color = $coverage >= 90 ? 'brightgreen' : ($coverage >= 75 ? 'yellow' : 'red');

file_put_contents($output, json_encode([
    'schemaVersion' => 1,
    'label' => 'coverage',
    'message' => sprintf('%.1f%%', $coverage),
    'color' => $color,
]) . "\n");

printf("Coverage badge: %.1f%% (%s) -> %s\n", $coverage, $color, $output);
