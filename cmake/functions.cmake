
# @fn thesis_copy_build
# @param TARGET_NAME target files
# @param FILES_LIST list of files to be copied
# Copies the target files to the target build folder.
function (thesis_copy_build TARGET_NAME FILE_INPUT FILE_OUT)
    add_custom_command (
        TARGET ${TARGET_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/${FILE_INPUT}
            ${CMAKE_CURRENT_BINARY_DIR}/${FILE_OUT}
        COMMENT "Copying ${FILE_INPUT} to ${CMAKE_CURRENT_BINARY_DIR}")
endfunction ()

