document.addEventListener("DOMContentLoaded", () => {
    const searchBtn = document.getElementById("search-btn");
    const usernameInput = document.getElementById("username");
    const apiKeyInput = document.getElementById("apiKey");
    const resultsContent = document.getElementById("results-content");

    searchBtn.addEventListener("click", async () => {
        const username = usernameInput.value.trim();
        const apiKey = apiKeyInput.value.trim();

        if (!username) {
            alert("Please enter a username.");
            return;
        }

        resultsContent.innerHTML = "Searching...";

        try {
            const response = await fetch("/search", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ username, api_key: apiKey }),
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const results = await response.text();
            resultsContent.textContent = results;
        } catch (error) {
            resultsContent.textContent = `An error occurred: ${error.message}`;
        }
    });
});