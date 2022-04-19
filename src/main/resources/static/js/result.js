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

    $("#sigreportoptions-dialogue").dialog({
        autoOpen: false,
        show: {
            effect: "blind",
            duration: 300
        }
    });


});

function downloadSvt(){
    let win = window.open("svt-request-form", "_blank");
    win.focus()
}

function openReportDialogue(){
    $("#sigreportoptions-dialogue").dialog("open");
    document.getElementById("getReportButton").focus();
//    $("#getReportButton").focus();
}

function getValidationReport(){
    let includeChain = "false";
    let includeSigDocs = "false";

    if ($("#includeChainOption").prop("checked")){
        includeChain = "true";
    }
    if ($("#includeSigDataOption").prop("checked")){
        includeSigDocs = "true";
    }

    $("#sigreportoptions-dialogue").dialog("close");

    window.open("report-request-form?certpath=" + includeChain + "&include-docs=" + includeSigDocs, "_blank");
}

function directReportRequest() {
    window.open("report-request-form", "_blank");
}
