(function () {
    var lastPathname;
    var BASE_URL = 'https://analytics.servers.do';

    function documentReady(fn) {
        if (document.readyState === "complete" || document.readyState === "interactive" || (window.performance && !window.performance.timing.domContentLoadedEventEnd)) setTimeout(fn, 1);
        else document.addEventListener("DOMContentLoaded", fn);
    }

    function pageview() {
        event();
    }

    function event(name, value) {
        if (location.pathname === lastPathname && !name) return;

        var sessionCount = 0, viewCount = 0, sessionTime = 0, sessionId = 0, isNew = 1;

        try {
            sessionId = (sessionStorage.getItem('_sessionId') || Math.random().toString(36).substr(2));
            sessionCount = (parseInt(localStorage.getItem('_implausible_sessions')) || 0);
            sessionTime = (parseInt(sessionStorage.getItem('_sessionTime')) || 1);
            viewCount = (parseInt(sessionStorage.getItem('_viewCount')) || 0);
            if (sessionCount) isNew = 0;

            if (!viewCount && !name) localStorage.setItem('_implausible_sessions', ++sessionCount);
            if (sessionId) sessionStorage.setItem('_sessionId', sessionId);
            if (!name) sessionStorage.setItem('_viewCount', ++viewCount);
        } catch(e){}

        var loadTime = ((window.performance.timing.domContentLoadedEventEnd - window.performance.timing.navigationStart) / 1000).toFixed(2);
        var isHeadless = !!(window.phantom || window._phantom || window.__nightmare || window.navigator.webdriver || window.Cypress);
        var width = window.innerWidth, referrer = document.referrer, href = location.href, host = location.hostname;
        var isBot = /bot|googlebot|crawler|spider|robot|crawling/i.test(navigator.userAgent);
        var rand = (Math.random() + 1).toString(36).substring(5);
        var lang = navigator.language || navigator.languages[0] || '';
        var img = document.createElement("img");

        var url = `${ BASE_URL }/o.png?host=${ encodeURIComponent(host) }&referrer=${ encodeURIComponent(referrer) }&href=${ encodeURIComponent(href) }&width=${ width }&bot=${ isBot ? 1 : 0 }&headless=${ isHeadless ? 1 : 0 }&load=${ loadTime }&views=${ viewCount }&time=${ sessionTime }&lang=${ lang }&new=${ isNew }&session=${ sessionCount }&sid=${ sessionId }&v=${ rand }`;
        if (window.__analytics_encryption_key) url += `&key=${ encodeURIComponent(window.__analytics_encryption_key) }`;
        if (value) url += `&value=${ value }`;
        if (name) url += `&event=${ name }`;

        if (!name) lastPathname = location.pathname;

        img.src = url;

        img.onerror = async function() {
            url = url.replace('/o.png?', '/o?');
            let response = await fetch(url);
            console.log('A.js fetch request replaces img request which encountered an error.', response);
        }

        document.body.appendChild(img);
    }

    setInterval(function () {
        try { sessionStorage.setItem('_sessionTime', ((parseInt(sessionStorage.getItem('_sessionTime')) || 1) + 1)) } catch(e){}
    }, 1000);

    documentReady(function() {
        window.addEventListener('visibilitychange', pageview);
        window.addEventListener('popstate', pageview);
        pageview();
    });

    window.implausible = event;
})();
