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
    $("#uploadedFileInput").fileinput({
        uploadUrl: "sigupload", // server upload action
        uploadAsync: false,
        showPreview: false,
        allowedFileExtensions: ['xml',"pdf","json","jose"],
        maxFileSize: maxFileSizeKb,
        maxFileCount: 1,
        language: lang,
        elErrorContainer: '#kv-error-2'
    }).on('filebatchpreupload', function (event, data, id, index) {
        $('#kv-success-2').html('<h4>Upload Status</h4><ul></ul>').hide();
    }).on('filebatchuploadsuccess', function (event, data) {
        let message = data.response.message;
        if (message !== undefined){
            alert(message);
        } else {
            setTimeout(function(){window.location="validate";},500);
        }
    });

});



