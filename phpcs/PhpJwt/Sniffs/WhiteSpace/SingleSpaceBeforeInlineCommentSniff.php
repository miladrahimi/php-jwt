<?php

declare(strict_types=1);

namespace PhpJwt\Sniffs\WhiteSpace;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Ensures a trailing `//` comment is separated from the code by exactly one space — no column alignment.
 */
class SingleSpaceBeforeInlineCommentSniff implements Sniff
{
    /**
     * {@inheritDoc}
     */
    public function register(): array
    {
        return [T_COMMENT];
    }

    /**
     * {@inheritDoc}
     */
    public function process(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();

        if (strpos($tokens[$stackPtr]['content'], '//') !== 0) {
            return;
        }

        $prev = $phpcsFile->findPrevious(T_WHITESPACE, $stackPtr - 1, null, true);
        if ($prev === false || $tokens[$prev]['line'] !== $tokens[$stackPtr]['line']) {
            return; // A standalone comment on its own line; only trailing comments are checked.
        }

        $before = $tokens[$stackPtr - 1];
        if ($before['code'] === T_WHITESPACE && $before['content'] === ' ') {
            return;
        }

        $fix = $phpcsFile->addFixableError(
            'Expected exactly one space between the code and the trailing comment.',
            $stackPtr,
            'Found'
        );

        if ($fix) {
            if ($before['code'] === T_WHITESPACE) {
                $phpcsFile->fixer->replaceToken($stackPtr - 1, ' ');
            } else {
                $phpcsFile->fixer->addContentBefore($stackPtr, ' ');
            }
        }
    }
}
