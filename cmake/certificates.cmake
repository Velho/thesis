# Test certificates
set (THESIS_TEST_CERTIFICATES
    "tests/certs/ca.pem"
    "tests/certs/cert-2048.pem"
    "tests/certs/pk-rsa-2048.pem"
    "tests/certs/ecsda/cert.pem"
    "tests/certs/ecsda/private-key.pem"
)

include (functions)

# @fn thesis_copy_certificates
# @param TARGET_NAME target name
# Target is required as the copy command is added
# to the POST_BUILD process.
function (thesis_copy_certificates TARGET_NAME)
    foreach (FILE_INPUT IN LISTS THESIS_TEST_CERTIFICATES)
        # Remove the tests/ from the output folder naming.
        string (REPLACE "tests/" "" FILE_CERT ${FILE_INPUT})
        thesis_copy_build (${TARGET_NAME} ${FILE_INPUT} ${FILE_CERT})
    endforeach ()
endfunction ()
