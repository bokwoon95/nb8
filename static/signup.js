const form = document.querySelector("form[data-signup-validation]");
if (form) {
    const insertionNodes = {};
    for (const node of form.querySelectorAll("[data-validation-errors]")) {
        const name = node.getAttribute("data-validation-errors");
        if (!name) {
            continue;
        }
        insertionNodes[name] = node;
    }
    form.addEventListener("submit", async function(event) {
        event.preventDefault();
        for (const insertionNode of Object.values(insertionNodes)) {
            insertionNode.innerHTML = "";
            const input = insertionNode.parentNode.querySelector("input");
            if (input) {
                input.classList.remove("b--invalid-red");
            }
        }
        const formData = new FormData(form);
        formData.set("dryRun", "true");
        const result = await (await fetch(form.action, {
            method: form.method,
            headers: {
                "Accept": "application/json",
            },
            body: formData,
        })).json();
        console.log(result);
        if (result.status.length > 8
            && result.status.startsWith("NB-")
            && result.status.charAt(8) == " "
            && result.status.charAt(3) == "0"
            && result.status.charAt(4) == "0") {
            if (formData.has("h-captcha-response")) {
                if (formData.get("h-captcha-response") == "") {
                    const insertionNode = document.querySelector("[data-validation-status]");
                    if (insertionNode) {
                        insertionNode.innerHTML = "NOTE: Solve the captcha";
                    } else {
                        console.log("NOTE: Solve the captcha");
                    }
                    return;
                }
            }
            for (const button of form.querySelectorAll("button[type=submit]")) {
                button.disabled = true;
            }
            const element = form.querySelector("[data-loading-spinner]");
            if (element) {
                element.innerHTML = `<div class="mr2">Loading</div><svg width="24" height="24" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><style>.spinner_ajPY{transform-origin:center;animation:spinner_AtaB .75s infinite linear}@keyframes spinner_AtaB{100%{transform:rotate(360deg)}}</style><path d="M12,1A11,11,0,1,0,23,12,11,11,0,0,0,12,1Zm0,19a8,8,0,1,1,8-8A8,8,0,0,1,12,20Z" opacity=".25"/><path d="M10.14,1.16a11,11,0,0,0-9,8.92A1.59,1.59,0,0,0,2.46,12,1.52,1.52,0,0,0,4.11,10.7a8,8,0,0,1,6.66-6.61A1.42,1.42,0,0,0,12,2.69h0A1.57,1.57,0,0,0,10.14,1.16Z" class="spinner_ajPY"/></svg>`;
            }
            form.submit();
            return;
        }
        for (const [name, values] of Object.entries(result.errors)) {
            const insertionNode = insertionNodes[name];
            if (!insertionNode) {
                console.log(name, values);
                continue;
            }
            for (const value of values) {
                let message = value;
                if (value.length > 8 && value.startsWith("NB-") && value[8] == " ") {
                    message = value.slice(8, value.length).trim();
                }
                const li = document.createElement("li");
                li.classList.add("f6", "invalid-red", "list-style-disc");
                li.innerText = message;
                insertionNode.appendChild(li);
                const input = insertionNode.parentNode.querySelector("input");
                if (input) {
                    input.classList.add("b--invalid-red");
                }
            }
        }
        const insertionNode = document.querySelector("[data-validation-status]");
        if (insertionNode) {
            insertionNode.innerHTML = "Please fix errors before continuing";
        }
    });
}
