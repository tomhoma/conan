document.getElementById('conan-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    const form = e.target;
    const data = new FormData(form);
    const params = new URLSearchParams();
    for (const [key, value] of data.entries()) {
        params.append(key, value);
    }
    const res = await fetch('/run', {
        method: 'POST',
        body: params,
    });
    document.getElementById('output').textContent = await res.text();
});
