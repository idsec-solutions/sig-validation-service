$(document).ready(function () {
    $('[id^=sigDataDiv]').hide();
    var windowHeight = window.innerHeight;
    windowHeight = parseInt((windowHeight - 115) * 94 / 100);
    var viewHeight = windowHeight > 100 ? windowHeight : 100;
    $('[id^=sigDataDisplayDiv]').css("height", viewHeight).attr("overflow", "auto");

    if ($("#pdfFrame").length){
        $('[id^=pdfFrame]').css("height", viewHeight)
    }

    $('pre code').each(function (i, block) {
        hljs.highlightBlock(block);
        $(this).css("height", viewHeight);
    });
});

function downloadSvt(){
    let win = window.open("issue-svt", "_blank");
    win.focus()
}
