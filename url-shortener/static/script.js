const form = document.getElementById("shorten-form");
const urlInput = document.getElementById("url-input");
const result = document.getElementById("result");
const shortUrlText = document.getElementById("short-url-text");
const copyBtn = document.getElementById("copy-btn");
const formError = document.getElementById("form-error");

form.addEventListener("submit", async (e) => {
    e.preventDefault();
    formError.classList.add("hidden");
    result.classList.add("hidden");

    const url = urlInput.value.trim();

    try {
        const response = await fetch("/shorten", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });
        const data = await response.json();

        if (!response.ok) {
            formError.textContent = data.error || "Something went wrong.";
            formError.classList.remove("hidden");
            return;
        }

        shortUrlText.textContent = data.short_url;
        result.classList.remove("hidden");
        urlInput.value = "";
    } catch (err) {
        formError.textContent = "Could not reach the server. Please try again.";
        formError.classList.remove("hidden");
    }
});

copyBtn.addEventListener("click", async () => {
    try {
        await navigator.clipboard.writeText(shortUrlText.textContent);
        copyBtn.textContent = "Copied!";
        setTimeout(() => (copyBtn.textContent = "Copy"), 1500);
    } catch (err) {
        alert("Failed to copy. Please copy manually.");
    }
});
