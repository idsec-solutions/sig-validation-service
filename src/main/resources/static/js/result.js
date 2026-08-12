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
    $('#sigRevisionDiv').hide();
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

// Height used for the display panels (mirrors the calculation in $(document).ready).
function currentViewHeight() {
    let windowHeight = ((window.innerHeight - 115) * 94) / 100;
    return windowHeight > 100 ? windowHeight : 100;
}

// Object URL of the currently displayed PDF blob, revoked before loading the next one.
let currentSignedObjectUrl = null;

// Loads the signed revision for one signature on demand via AJAX, renders it into #sigRevisionContent, and shows the
// box. Called with just the signature index (an integer is allowed in th:onclick; a String would not be). The
// document type is page-level and read from the box's data-doc-type attribute - it decides how the response is
// rendered (PDF as an embed, other types as text).
function showSignedContent(index) {
    const type = document.getElementById('sigRevisionDiv').dataset.docType;
    const content = document.getElementById('sigRevisionContent');
    content.innerHTML = '';
    if (currentSignedObjectUrl) {
        URL.revokeObjectURL(currentSignedObjectUrl);
        currentSignedObjectUrl = null;
    }
    const height = currentViewHeight();
    $('#sigRevisionDiv').fadeIn(700);

    if (type === 'PDF') {
        $.ajax({
            url: 'inlineDocument?id=' + index,
            xhrFields: {responseType: 'blob'},
            success: function (blob) {
                currentSignedObjectUrl = URL.createObjectURL(blob);
                content.innerHTML = '<embed class="w-100" type="application/pdf" style="height:' + height + 'px;" src="'
                    + currentSignedObjectUrl + '">';
            },
            error: function () {
                content.innerHTML = '<div class="p-3 text-danger">Unable to load the signed document.</div>';
            }
        });
    } else {
        $.ajax({
            url: 'inlineDocument?id=' + index,
            dataType: 'text',
            success: function (docText) {
                const pre = document.createElement('pre');
                pre.className = 'white-space-pre-wrap';
                pre.style.height = height + 'px';
                const code = document.createElement('code');
                code.textContent = docText;
                pre.appendChild(code);
                content.appendChild(pre);
                if (window.hljs) {
                    hljs.highlightElement(code);
                }
            },
            error: function () {
                content.innerHTML = '<div class="p-3 text-danger">Unable to load the signed document.</div>';
            }
        });
    }
}
