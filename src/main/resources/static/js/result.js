/*
 * Copyright (c) 2022. IDsec Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

$(document).ready(function () {
    $('[id^=sigDataDiv]').hide();
    let windowHeight = window.innerHeight;
    windowHeight = ((windowHeight - 115) * 94) / 100;
    let viewHeight = windowHeight > 100 ? windowHeight : 100;
    $('[id^=sigDataDisplayDiv]').css("height", viewHeight).attr("overflow", "auto");

    if ($("#pdfFrame").length){
        $('[id^=pdfFrame]').css("height", viewHeight)
    }

    $('pre code').each(function (i, block) {
        hljs.highlightBlock(block);
        $(this).css("height", viewHeight);
    });

});

function downloadSvt(newTab){
    if (newTab) {
        let win = window.open("issue-svt-internal", "_blank");
        win.focus()
    } else {
        window.location = "issue-svt-internal";
    }
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

    window.open("report-internal?certpath=" + includeChain + "&include-docs=" + includeSigDocs, "_blank");
}

function directReportRequest() {
    window.open("report-internal", "_blank");
}
