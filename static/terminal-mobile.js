/*
 * Mobile ergonomics for the xterm.js SSH terminal.
 *
 * Mobile soft keyboards give you no Esc/Tab/Ctrl/arrow keys, and when the
 * keyboard opens it covers the active line so you can't see what you type.
 * This module adds, on touch devices only:
 *
 *   1. A scrollable on-screen key bar (Esc, Tab, arrows, Ctrl-C/D/Z, and the
 *      punctuation that is awkward to reach on phone keyboards) that sends the
 *      matching escape sequences over the same channel as normal keystrokes.
 *   2. visualViewport handling that shrinks the terminal to the space above the
 *      keyboard and scrolls the prompt into view, so typing is visible.
 *   3. Tap-to-focus, so tapping the terminal opens the keyboard.
 *
 * Everything is a no-op on devices with a fine pointer (i.e. desktops), so the
 * existing desktop behaviour is unchanged.
 *
 * Usage:
 *   TerminalMobile.init({ term, container, fit, sendInput });
 *     term      - the xterm.js Terminal instance
 *     container - the element term.open() was called on
 *     fit       - function that refits the terminal (and notifies the server)
 *     sendInput - function(data) that sends raw input bytes to the SSH session
 */
(function () {
    'use strict';

    // label: what the button shows; seq: the bytes sent to the shell.
    var KEYS = [
        { label: 'Esc', seq: '\x1b' },
        { label: 'Tab', seq: '\t' },
        { label: '↑', seq: '\x1b[A' },   // up
        { label: '↓', seq: '\x1b[B' },   // down
        { label: '←', seq: '\x1b[D' },   // left
        { label: '→', seq: '\x1b[C' },   // right
        { label: '^C', seq: '\x03' },
        { label: '^D', seq: '\x04' },
        { label: '^Z', seq: '\x1a' },
        { label: '|', seq: '|' },
        { label: '/', seq: '/' },
        { label: '~', seq: '~' },
        { label: '-', seq: '-' }
    ];

    function isTouch() {
        return ('ontouchstart' in window) ||
            (window.matchMedia && window.matchMedia('(pointer: coarse)').matches);
    }

    function injectStyles() {
        if (document.getElementById('term-mobile-styles')) return;
        var css = [
            '.term-mobile-keys{display:flex;flex:0 0 auto;gap:6px;overflow-x:auto;',
            '-webkit-overflow-scrolling:touch;padding:6px 4px;margin-bottom:4px;',
            'scrollbar-width:none;}',
            '.term-mobile-keys::-webkit-scrollbar{display:none;}',
            '.term-key{flex:0 0 auto;min-width:44px;min-height:40px;padding:6px 12px;',
            'font-family:var(--bs-font-monospace,monospace);font-size:15px;line-height:1;',
            'color:#c9d1d9;background:#161b22;border:1px solid #30363d;border-radius:6px;',
            'cursor:pointer;-webkit-user-select:none;user-select:none;}',
            '.term-key:active{background:#30363d;}'
        ].join('');
        var style = document.createElement('style');
        style.id = 'term-mobile-styles';
        style.textContent = css;
        document.head.appendChild(style);
    }

    // Fire on pointer-down and preventDefault so the xterm textarea keeps focus
    // — otherwise tapping a button blurs it and dismisses the soft keyboard.
    function onPress(el, term, action) {
        var handler = function (e) {
            e.preventDefault();
            action();
            if (term && typeof term.focus === 'function') term.focus();
        };
        el.addEventListener('mousedown', handler);
        el.addEventListener('touchstart', handler, { passive: false });
    }

    function buildKeyBar(term, sendInput) {
        var bar = document.createElement('div');
        bar.className = 'term-mobile-keys';
        bar.setAttribute('role', 'toolbar');
        bar.setAttribute('aria-label', 'Terminal special keys');
        KEYS.forEach(function (k) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'term-key';
            btn.textContent = k.label;
            btn.setAttribute('aria-label', k.label);
            onPress(btn, term, function () { sendInput(k.seq); });
            bar.appendChild(btn);
        });
        return bar;
    }

    function debounce(fn, ms) {
        var t = null;
        return function () {
            if (t) clearTimeout(t);
            t = setTimeout(fn, ms);
        };
    }

    function init(opts) {
        if (!opts || !opts.term || typeof opts.sendInput !== 'function') return;
        if (!isTouch()) return;

        var term = opts.term;
        var container = opts.container || term.element;
        var fit = typeof opts.fit === 'function' ? opts.fit : function () {};
        if (!container) return;

        injectStyles();

        // 1. On-screen key bar, inserted directly above the terminal.
        if (container.parentNode) {
            container.parentNode.insertBefore(buildKeyBar(term, opts.sendInput), container);
        }

        // 2. Tapping the terminal focuses it (opens the soft keyboard).
        container.addEventListener('touchstart', function () {
            if (typeof term.focus === 'function') term.focus();
        }, { passive: true });

        // 3. Keep the terminal sized to the space above the keyboard. The
        //    soft keyboard changes visualViewport, not window size, so the
        //    template's window-resize handler never fires for it.
        var vv = window.visualViewport;
        if (vv) {
            var origMinHeight = container.style.minHeight;
            var adjust = debounce(function () {
                // Keyboard open when the visual viewport is much shorter than
                // the layout viewport.
                if (window.innerHeight - vv.height > 120) {
                    var top = container.getBoundingClientRect().top;
                    var avail = vv.height - top - 4;
                    if (avail < 140) avail = 140;
                    container.style.height = avail + 'px';
                    container.style.minHeight = '0px';
                } else {
                    container.style.height = '';
                    container.style.minHeight = origMinHeight;
                }
                fit();
                if (typeof term.scrollToBottom === 'function') term.scrollToBottom();
            }, 80);
            vv.addEventListener('resize', adjust);
            vv.addEventListener('scroll', adjust);
        }
    }

    window.TerminalMobile = { init: init };
})();
