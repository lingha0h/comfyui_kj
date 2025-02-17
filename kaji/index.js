function loadCSS(stylesheets) {
    stylesheets.forEach((link) => {
        const styleTag = document.createElement("link");
        styleTag.rel = "stylesheet";
        styleTag.href = link.getAttribute("href");
        document.head.appendChild(styleTag);
    });
}

function loadJS(scripts) {
    scripts.forEach((script) => {
        const scriptTag = document.createElement("script");
        const src = script.getAttribute("src");
        if (src) {
            scriptTag.src = src;
            scriptTag.defer = true;
            scriptTag.type = "module";  
            scriptTag.onload = () => {
                console.log(`Script loaded: ${src}`);
            };
            scriptTag.onerror = (e) => {
                console.error(`Error loading script: ${src}`, e);
            };
            document.body.appendChild(scriptTag);
        }
    });
}


async function loadPluginUI() {
    try {
        console.log("Loading plugin UI...");

        const response = await fetch("/kaji/index.html");
        console.log("获取插件的 HTML 文件", response);
        if (!response.ok) throw new Error("Network response was not ok");

        const htmlContent = await response.text();
        const container = document.createElement("div");
        container.innerHTML = htmlContent;

        const stylesheets = container.querySelectorAll('link[rel="stylesheet"]');
        loadCSS(stylesheets);
        console.log("动态加载 CSS 样式", stylesheets);


        const scripts = container.querySelectorAll("script");
        loadJS(scripts);
        console.log("动态加载 JS 脚本", scripts);

        const pluginElement = container.querySelector("#kaji-plugin-ui");
        if (pluginElement) {
            document.body.appendChild(pluginElement);
        }
        console.log("将插件内容插入到页面中", pluginElement);

    } catch (error) {
        console.error("Error loading plugin UI:", error);
    }
}

setTimeout(() => {
    console.log("初始化咔叽UI");
    loadPluginUI();
}, 1000);

