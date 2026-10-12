/**
 * Aegis Cybersecurity Console — Interactive Client Engine v2.0
 * Powers:
 * - Theme Persistence (Obsidian Dark / Clean Enterprise Light)
 * - Approvals Queue Interactive Risk Filtering (All / Critical / High / Medium)
 * - Blast Radius Interactive Multi-File Diff Switcher
 * - Unified / Split Diff View Toggle
 * - Keyboard Shortcuts (Ctrl+K, A, E, D, Esc)
 * - One-Click Cryptographic Hash Copy with Tooltip
 * - Real-Time Autonomous Event Simulation Ticker
 */

(function () {
    const THEME_STORAGE_KEY = 'warden-theme';
    const THEMES = { DARK: 'dark', LIGHT: 'light' };

    function getStoredTheme() {
        try {
            return localStorage.getItem(THEME_STORAGE_KEY) || THEMES.DARK;
        } catch (e) {
            return THEMES.DARK;
        }
    }

    function applyTheme(theme) {
        document.documentElement.dataset.theme = theme;
        const icon = document.getElementById('theme-icon');
        const label = document.getElementById('theme-label');

        if (icon && label) {
            if (theme === THEMES.LIGHT) {
                icon.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`;
                label.textContent = 'Light';
            } else {
                icon.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`;
                label.textContent = 'Dark';
            }
        }
    }

    function toggleTheme() {
        const currentTheme = document.documentElement.dataset.theme || THEMES.DARK;
        const newTheme = currentTheme === THEMES.DARK ? THEMES.LIGHT : THEMES.DARK;
        try {
            localStorage.setItem(THEME_STORAGE_KEY, newTheme);
        } catch (e) {
            console.warn(e);
        }
        applyTheme(newTheme);
    }

    // Apply immediately to prevent flicker
    applyTheme(getStoredTheme());

    document.addEventListener('DOMContentLoaded', function () {
        // Theme button
        const toggleBtn = document.getElementById('theme-toggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', toggleTheme);
        }
        applyTheme(getStoredTheme());

        // Keyboard Shortcut: Ctrl+K or Cmd+K
        document.addEventListener('keydown', function (e) {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                const search = document.getElementById('global-search');
                if (search) search.focus();
            }
        });

        // Copy Hash Chips
        document.querySelectorAll('.copy-hash-btn').forEach(btn => {
            btn.addEventListener('click', function (e) {
                e.preventDefault();
                e.stopPropagation();
                const hash = this.getAttribute('data-hash');
                if (hash && navigator.clipboard) {
                    navigator.clipboard.writeText(hash).then(() => {
                        const originalHTML = this.innerHTML;
                        this.innerHTML = `✓ Copied!`;
                        setTimeout(() => {
                            this.innerHTML = originalHTML;
                        }, 2000);
                    });
                }
            });
        });

        // Approval queue filters and search share one state so they never override each other.
        const approvalSearch = document.getElementById('approval-search');
        const queueRoot = document.getElementById('approval-queue-list');
        if (queueRoot) {
            const filterPills = Array.from(document.querySelectorAll('.filter-pill'));
            const queueCards = Array.from(queueRoot.querySelectorAll('.approval-item-card'));
            const resultCount = document.getElementById('approval-results-count');
            let activeRiskFilter = 'all';

            // Derive counts from the exact rendered queue rather than hardcoded values.
            filterPills.forEach(pill => {
                const filter = pill.getAttribute('data-filter') || 'all';
                const count = filter === 'all'
                    ? queueCards.length
                    : queueCards.filter(card => (card.dataset.risk || '').toLowerCase() === filter).length;
                const countEl = pill.querySelector('.filter-count');
                if (countEl) countEl.textContent = String(count);
            });

            let empty = document.getElementById('approval-search-empty');
            if (!empty) {
                empty = document.createElement('div');
                empty.id = 'approval-search-empty';
                empty.className = 'queue-empty-state';
                empty.hidden = true;
                empty.innerHTML = '<div class="empty-state-icon">⌕</div><h2>No matching actions</h2><p>Try a different search term or risk filter.</p>';
                queueRoot.appendChild(empty);
            }

            function applyApprovalFilters() {
                const query = approvalSearch ? approvalSearch.value.trim().toLowerCase() : '';
                let visibleCount = 0;
                queueCards.forEach(card => {
                    const risk = (card.dataset.risk || '').toLowerCase();
                    const matchesRisk = activeRiskFilter === 'all' || risk === activeRiskFilter;
                    const matchesText = !query || card.textContent.toLowerCase().includes(query);
                    const visible = matchesRisk && matchesText;
                    card.hidden = !visible;
                    if (visible) visibleCount += 1;
                });
                empty.hidden = visibleCount > 0;
                if (resultCount) resultCount.textContent = `${visibleCount} of ${queueCards.length} actions`;
            }

            filterPills.forEach(pill => {
                pill.addEventListener('click', function () {
                    activeRiskFilter = this.getAttribute('data-filter') || 'all';
                    filterPills.forEach(item => {
                        const selected = item === this;
                        item.classList.toggle('active', selected);
                        item.setAttribute('aria-pressed', String(selected));
                    });
                    applyApprovalFilters();
                });
            });
            if (approvalSearch) approvalSearch.addEventListener('input', applyApprovalFilters);
            applyApprovalFilters();
        }

        // Blast Radius Tab Switcher
        document.querySelectorAll('.tab-btn').forEach(tab => {
            tab.addEventListener('click', function () {
                const parent = this.closest('.tabs-container');
                if (!parent) return;

                parent.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
                this.classList.add('active');

                const targetTab = this.getAttribute('data-tab');
                const contentContainer = document.getElementById(parent.getAttribute('data-content-target'));
                if (contentContainer) {
                    contentContainer.querySelectorAll('.tab-pane').forEach(pane => {
                        pane.classList.remove('active');
                        if (pane.id === targetTab) {
                            pane.classList.add('active');
                        }
                    });
                }
            });
        });

        // Blast Radius Interactive File Tree Diff Switcher
        const fileItems = document.querySelectorAll('.file-tree-item');
        fileItems.forEach(item => {
            item.addEventListener('click', function () {
                fileItems.forEach(f => f.classList.remove('active'));
                this.classList.add('active');

                const fileIndex = this.getAttribute('data-file-index');
                const diffPanes = document.querySelectorAll('.file-diff-pane');
                diffPanes.forEach(pane => {
                    pane.style.display = 'none';
                    if (pane.getAttribute('data-pane-index') === fileIndex) {
                        pane.style.display = 'block';
                    }
                });
            });
        });

        // Unified vs Split Diff Toggle
        const btnUnified = document.getElementById('btn-diff-unified');
        const btnSplit = document.getElementById('btn-diff-split');
        if (btnUnified && btnSplit) {
            btnUnified.addEventListener('click', function () {
                btnUnified.classList.add('active');
                btnSplit.classList.remove('active');
                document.querySelectorAll('.diff-box').forEach(b => b.classList.remove('split-mode'));
            });
            btnSplit.addEventListener('click', function () {
                btnSplit.classList.add('active');
                btnUnified.classList.remove('active');
                document.querySelectorAll('.diff-box').forEach(b => b.classList.add('split-mode'));
            });
        }

        // Live Event Feed Simulation Ticker
        const eventStream = document.querySelector('.events-stream');
        if (eventStream) {
            const telemetryPool = [
                { text: 'CodeAgent requested workspace cache flush', status: 'cyan' },
                { text: 'Policy L1 verified lease #LSE-901 valid', status: 'emerald' },
                { text: 'DBAgent proposed index re-build on auth_tokens', status: 'amber' },
                { text: 'Checkpoint snapshot chk_91a0 verified by checkpointer', status: 'cyan' },
                { text: 'Write-ahead audit journal record #WAL-810 written', status: 'emerald' }
            ];

            setInterval(() => {
                const item = telemetryPool[Math.floor(Math.random() * telemetryPool.length)];
                const now = new Date();
                const timeStr = now.toTimeString().split(' ')[0];

                const line = document.createElement('div');
                line.className = 'event-line';
                line.innerHTML = `
                    <span class="event-timestamp tabular-nums">${timeStr}</span>
                    <span class="event-dot" style="background: var(--color-${item.status});"></span>
                    <span>${item.text}</span>
                `;

                eventStream.insertBefore(line, eventStream.firstChild);
                if (eventStream.children.length > 6) {
                    eventStream.removeChild(eventStream.lastChild);
                }
            }, 9000);
        }
    });
})();

