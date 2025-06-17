(function(){
    function obf_setAjaxBaseAddress(obf_base) {
        window.XMLHttpRequest.prototype.open = function(obf_method, obf_url, obf_async, obf_user, obf_password) {
            try {
                if(obf_url.startsWith("/")) {
                    obf_url = obf_base + obf_url;
                }
                return open.call(this, obf_method, obf_url, ...obf_rest);
            } catch (obf_error) {
                return null;
            }
        }
    }

    <<<PRELOAD_CODE>>>
})();
