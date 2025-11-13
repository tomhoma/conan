document.addEventListener("DOMContentLoaded", () => {
    const searchBtn = document.getElementById("search-btn");
    const batchSearchBtn = document.getElementById("batch-search-btn");
    const usernameInput = document.getElementById("username");
    const apiKeyInput = document.getElementById("apiKey");
    const batchUsernamesInput = document.getElementById("batch-usernames");
    const resultsContent = document.getElementById("results-content");
    const loadingIndicator = document.getElementById("loading");

    // Check server health on load
    checkHealth();

    async function checkHealth() {
        try {
            const response = await fetch("/health");
            const data = await response.json();
            console.log("Server health:", data);
        } catch (error) {
            console.error("Server health check failed:", error);
        }
    }

    function showLoading() {
        loadingIndicator.style.display = "block";
        resultsContent.style.display = "none";
        searchBtn.disabled = true;
        if (batchSearchBtn) batchSearchBtn.disabled = true;
    }

    function hideLoading() {
        loadingIndicator.style.display = "none";
        resultsContent.style.display = "block";
        searchBtn.disabled = false;
        if (batchSearchBtn) batchSearchBtn.disabled = false;
    }

    function formatResults(text) {
        // Convert plain text results to formatted HTML
        return text
            .replace(/\[\\+\]/g, '<span class="success">✓</span>')
            .replace(/\[-\]/g, '<span class="error">✗</span>')
            .replace(/\[\*\]/g, '<span class="info">ℹ</span>')
            .replace(/\[\?\]/g, '<span class="warning">?</span>')
            .replace(/(https?:\/\/[^\s]+)/g, '<a href="$1" target="_blank">$1</a>');
    }

    searchBtn.addEventListener("click", async () => {
        const username = usernameInput.value.trim();
        const apiKey = apiKeyInput.value.trim();

        if (!username) {
            alert("Please enter a username.");
            return;
        }

        showLoading();

        try {
            const startTime = Date.now();
            const response = await fetch("/search", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ username, api_key: apiKey || null }),
            });

            const results = await response.text();
            const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

            if (!response.ok) {
                resultsContent.innerHTML = `<div class="error-box">
                    <h3>Search Failed</h3>
                    <p>${results}</p>
                </div>`;
            } else {
                resultsContent.innerHTML = `
                    <div class="success-box">
                        <h3>Search completed in ${elapsed}s</h3>
                    </div>
                    <pre>${results}</pre>
                `;
            }
        } catch (error) {
            resultsContent.innerHTML = `<div class="error-box">
                <h3>Error</h3>
                <p>${error.message}</p>
                <p>Please check your connection and try again.</p>
            </div>`;
        } finally {
            hideLoading();
        }
    });

    // Allow Enter key to submit
    usernameInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            searchBtn.click();
        }
    });

    // Batch search functionality
    if (batchSearchBtn && batchUsernamesInput) {
        batchSearchBtn.addEventListener("click", async () => {
            const usernamesText = batchUsernamesInput.value.trim();
            const apiKey = apiKeyInput.value.trim();

            if (!usernamesText) {
                alert("Please enter at least one username (one per line).");
                return;
            }

            const usernames = usernamesText.split("\n").map(u => u.trim()).filter(u => u.length > 0);

            if (usernames.length === 0) {
                alert("No valid usernames found.");
                return;
            }

            if (usernames.length > 10) {
                if (!confirm(`You are about to search ${usernames.length} usernames. This may take a while. Continue?`)) {
                    return;
                }
            }

            showLoading();
            resultsContent.innerHTML = `<p>Searching ${usernames.length} username(s)...</p>`;

            try {
                const startTime = Date.now();
                const response = await fetch("/batch-search", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ usernames, api_key: apiKey || null }),
                });

                const data = await response.json();
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

                if (!response.ok) {
                    throw new Error("Batch search failed");
                }

                // Format batch results
                let html = `<div class="success-box"><h3>Batch search completed in ${elapsed}s</h3></div>`;
                html += '<div class="batch-results">';

                data.results.forEach(result => {
                    const statusClass = result.success ? "success" : "error";
                    const icon = result.success ? "✓" : "✗";
                    html += `
                        <div class="batch-result ${statusClass}">
                            <span class="batch-icon">${icon}</span>
                            <span class="batch-username">${result.username}</span>
                            <span class="batch-message">${result.message}</span>
                            ${result.success ? `<span class="batch-count">${result.profile_count} profiles</span>` : ''}
                        </div>
                    `;
                });

                html += '</div>';
                resultsContent.innerHTML = html;
            } catch (error) {
                resultsContent.innerHTML = `<div class="error-box">
                    <h3>Batch Search Error</h3>
                    <p>${error.message}</p>
                </div>`;
            } finally {
                hideLoading();
            }
        });
    }
});