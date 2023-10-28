const form = document.querySelector("form[data-login-validation]");
if (form) {
    form.addEventListener("submit", function(event) {
        event.preventDefault();
        const formData = new FormData(form);
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
        const element = form.querySelector("[data-loading-spinner]");
        if (element) {
            element.innerHTML = `<div class="mr2">Loading</div><svg width="24" height="24" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><style>.spinner_ajPY{transform-origin:center;animation:spinner_AtaB .75s infinite linear}@keyframes spinner_AtaB{100%{transform:rotate(360deg)}}</style><path d="M12,1A11,11,0,1,0,23,12,11,11,0,0,0,12,1Zm0,19a8,8,0,1,1,8-8A8,8,0,0,1,12,20Z" opacity=".25"/><path d="M10.14,1.16a11,11,0,0,0-9,8.92A1.59,1.59,0,0,0,2.46,12,1.52,1.52,0,0,0,4.11,10.7a8,8,0,0,1,6.66-6.61A1.42,1.42,0,0,0,12,2.69h0A1.57,1.57,0,0,0,10.14,1.16Z" class="spinner_ajPY"/></svg>`;
        }
        form.submit();
    });
}
