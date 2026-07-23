<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests;

/**
 * Runs every script in examples/ end to end and asserts it exits cleanly,
 * so the runnable examples can never silently drift from the library.
 */
class ExamplesScriptsTest extends TestCase
{
    public function test_every_example_script_it_should_run_successfully(): void
    {
        $scripts = glob(__DIR__ . '/../examples/*.php');
        $this->assertNotEmpty($scripts, 'No example scripts were found.');

        foreach ($scripts as $script) {
            $name = basename($script);

            if ($name === 'eddsa.php' && !extension_loaded('sodium')) {
                continue; // EdDSA needs ext-sodium
            }

            $output = [];
            $exitCode = 0;
            exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($script) . ' 2>&1', $output, $exitCode);

            $this->assertSame(0, $exitCode, "Example {$name} failed:\n" . implode("\n", $output));
            $this->assertStringContainsString('Verified claims', implode("\n", $output), "Example {$name} did not verify.");
        }
    }
}
