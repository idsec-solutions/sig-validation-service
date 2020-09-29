$(document).ready(function () {
    $('#metadataViewDiv').hide();
    var windowHeight = window.innerHeight;
    windowHeight = parseInt((windowHeight - 115) * 94 / 100);
    var viewHeight = windowHeight > 100 ? windowHeight : 100;
    $('#metadataDisplayDiv').css("height", viewHeight)
    $('#metadataDisplayDiv').attr("overflow", "auto")

    if ($("#pdfFrame").length){
        $("#pdfFrame").css("height", viewHeight)
    }

    $('pre code').each(function (i, block) {
        hljs.highlightBlock(block);
        $(this).css("height", viewHeight);
    });
});

function downloadSvt(type){

    if (type ===0){
        let win = window.open("xmldoc?target=svt", "_blank");
        win.focus()
    }
    if (type ===1){
        let win = window.open("pdfdoc?target=svt", "_blank");
        win.focus()
    }
}
