
# if the thesis is added as subdirectory,
# how to correctly resolve the copying process,
# even if it's called from a different root folder,
# ${THESIS_PROJECT_DIR}
set (THESIS_TEST_CERTIFICATES
    "tests/certs/ca.pem"
    "tests/certs/cert-2048.pem"
    "tests/certs/pk-rsa-2048.pem"
    "tests/certs/ecsda/cert.pem"
    "tests/certs/ecsda/private-key.pem"
)

include (functions)

# can be set outside of certificates to control the subdir name
set (THESIS_PROJECT_FOLDER_NAME "thesis")

# @fn thesis_copy_certificates
# @param TARGET_NAME target name
# Target is required as the copy command is added
# to the POST_BUILD process.
function (thesis_copy_certificates TARGET_NAME)
    # build_as_library defined out of scope.
    message ("copy_certs : ${THESIS_BUILD_AS_LIBRARY}")

    foreach (FILE_INPUT IN LISTS THESIS_TEST_CERTIFICATES)
        set (THESIS_FILE_INPUT "${FILE_INPUT}")
        set (THESIS_FILE_REGEX "tests/")

        # append the project_folder_name if built as library.
        if (${THESIS_BUILD_AS_LIBRARY})
            set (THESIS_FILE_INPUT "${THESIS_PROJECT_FOLDER_NAME}/${FILE_INPUT}")
            set (THESIS_FILE_REGEX "thesis/tests")
        endif ()

        # remove the tests/ from the output folder naming.
        string (REPLACE ${THESIS_FILE_REGEX} "" FILE_CERT ${FILE_INPUT})
        thesis_copy_build (${TARGET_NAME} ${THESIS_FILE_INPUT} ${FILE_CERT})
    endforeach ()
endfunction ()
