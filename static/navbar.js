const navbar = document.createElement("div");
navbar.style.position = "fixed";
navbar.style.top = "0";
navbar.style.width = "100vw";
navbar.style.height = "35px";
navbar.style.backgroundColor = "black";
document.body.prepend(navbar);
const marginTop = parseInt(window.getComputedStyle(document.body).marginTop);
const height = parseInt(navbar.style.height);
document.body.style.marginTop = `${marginTop + height}px`;