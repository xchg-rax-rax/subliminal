
function deleteNote(note_id) {
    fetch('/delete-note', {
        method: 'POST',
        body: JSON.stringify({note_id: note_id})
    }).then((_res) => {
        window.location.href = "/"
    });
}

function updateScanType(scan_type) {
    document.getElementById('scan_type').value = scan_type;
}

function updateScanStatus(new_status) {
    status_colours = ['primary','warning','success','danger']
    status_text_badge = ['Ready','In Progress', 'Finished', 'Failed']
    status_text_btn = ['Ready','In Progress', 'View Results', 'Retry']
    equal = true
    if (new_status.length != current_status.length) {
        return
    }
    for (var i =0; i < new_status.length; i++) {
        if (new_status[i] != current_status[i]) {
            badge = document.getElementById("scan-"+i+"-badge")
            bage.classList.remove('badge-'+status_colours[current_status[i]])
            bage.classList.add('badge-'+status_colours[new_status[i]])
            badge.innerHTML = status_text_badge[new_status[i]]
            btn = document.getElementById("scan-"+i+"-button")
            btn.classList.remove('btn-'+status_colours[current_status[i]])
            btn.classList.add('btn-'+status_colours[new_status[i]])
            btn.innerHTML = status_text_btn[new_status[i]]
        }
    }
}
