// https://til.simonwillison.net/javascript/dropdown-menu-with-details-summary
document.body.parentElement.addEventListener('click', (ev) => {
    /* Close any open details elements that this click is outside of */
    var target = ev.target;
    var detailsClickedWithin = null;
    while (target && target.tagName != 'DETAILS') {
        target = target.parentNode;
    }
    if (target && target.tagName == 'DETAILS') {
        detailsClickedWithin = target;
    }
    Array.from(document.getElementsByTagName('details')).filter(
        (details) => details.open && details != detailsClickedWithin && !details.hasAttribute("data-dont-autoclose-details")
    ).forEach(details => details.open = false);
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
            setTimeout(function() {
                parentElement.style.display = "none";
            }, 100);
            return;
        }
    });
}

const element = document.querySelector("[data-go-back]");
if (element && element.tagName == "A") {
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
