
# @fn thesis_copy_build
# @param TARGET_NAME target files
# @param FILES_LIST list of files to be copied
# Copies the target files to the build folder.
# @notes
# The function assumes the input list of files is contained
# under the CMAKE_CURRENT_SOURCE_DIR.
# For easy debugging make double copies to the build
# folder and the tests folder under build folder.
function (thesis_copy_build TARGET_NAME FILES_LIST)
    foreach (FILE_INPUT IN LISTS FILES_LIST)
        add_custom_command (
            TARGET ${TARGET_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy
                "${CMAKE_CURRENT_SOURCE_DIR}/${FILE_INPUT}"
                "${CMAKE_CURRENT_BINARY_DIR}/${FILE_INPUT}"
            COMMAND ${CMAKE_COMMAND} -E copy
                "${CMAKE_CURRENT_SOURCE_DIR}/${FILE_INPUT}"
                "${CMAKE_BINARY_DIR}/${FILE_INPUT}"
                COMMENT "Copying test certificates and private keys to binary folder."
        )
    endforeach ()
endfunction ()

