document.body.parentElement.addEventListener("click", (event) => {
    let activeDetails = null;
    let element = event.target;
    while (element != null) {
        if (element.tagName != "DETAILS") {
            element = element.parentElement;
            continue;
        }
        activeDetails = element;
        break;
    }
    for (const details of document.querySelectorAll("details[data-autoclose-details]")) {
        if (details.open && details != activeDetails) {
            details.open = false;
        }
    }
});

for (const element of document.querySelectorAll("[data-dismiss-alert]")) {
    element.addEventListener("click", function() {
        let parentElement = element.parentElement;
        while (parentElement != null) {
            const role = parentElement.getAttribute("role");
            if (role != "alert") {
                parentElement = parentElement.parentElement;
                continue;
            }
            parentElement.style.transition = "opacity 100ms linear";
            parentElement.style.opacity = "0";
            setTimeout(function() { parentElement.style.display = "none" }, 100);
            return;
        }
    });
}

for (const element of document.querySelectorAll("[data-go-back]")) {
    if (element.tagName != "A") {
        continue;
    }
    element.addEventListener("click", function(event) {
        if (document.referrer && history.length > 2 && !event.ctrlKey && !event.metaKey) {
            event.preventDefault();
            history.back();
        }
    });
}

for (const element of document.querySelectorAll("[data-disable-click-selection]")) {
    element.addEventListener("mousedown", function(event) {
        // https://stackoverflow.com/a/43321596
        if (event.detail > 1) {
            event.preventDefault();
        }
    });
}
