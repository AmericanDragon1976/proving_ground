#include <json/json.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h> 

#include <sys/socket.h>
#include <netinet/in.h>

#include <uv.h>

#include <signal.h>
#include <ctype.h>

/*
 * Call back creating buffer that libuv functions need. 
 */
uv_buf_t 
 alloc_buffer(uv_handle_t *handle, size_t suggested_size) 
{printf("alloc buffer \n");
    return uv_buf_init((char*) malloc(suggested_size), suggested_size);             //FREE for this Malloc ?
}

/*
 * Call back triggered when a child process finishes and returns. Sends the client the data from the 
 * process run and the origional hook that was sent when the process was launched. 
 */
void 
child_exit(uv_process_t *req, int exit_status, int term_signal)
{ printf("child exit called \n");
//fprintf(stderr, "Process exited with status %d, signal %d\n", exit_status, term_signal);
    char                    *reply_txt = NULL;

    printf("exit_status: %d, term signal: %d\n", exit_status, term_signal); 
    uv_close((uv_handle_t *) req, NULL);
    // DO I NEED TO CALL UV_CLOSE ON THE PIPES TOO??   
}

/*
 * Call back triggered when a running child process sends data to standard out. The data is captured and saved with the process so that 
 * it can later be sent back to the client. 
 */
void 
read_out(uv_stream_t *out_pipe, ssize_t nread, uv_buf_t buf)
{printf("read_out\n");
}

/*
 * Call back triggered when a running child process sends data to standard error. the data is captured and saved with the process so that 
 * it can later be sent back to the client. 
 */
void 
read_err(uv_stream_t *err_pipe, ssize_t nread, uv_buf_t buf)
{printf("read_err\n");
}

 uv_loop_t       *loop;

int 
main ()
{printf("Main \n");
	char 					command[] = "/home/eduard/workspace/hooky/removedir";
    uv_stdio_container_t    child_stdio[3];
    int                     len, ret;
    char                    *args[3], *reply, payload[] = " ";
    bool                    file_exists;
    uv_process_options_t    options = {0};
    uv_pipe_t               out_pipe, err_pipe;
    uv_process_t            child_req;

    loop = uv_loop_new();

    uv_pipe_init(loop, &err_pipe, 1);
    uv_pipe_init(loop, &out_pipe, 1);
    uv_pipe_open(&err_pipe, 0);
    uv_pipe_open(&out_pipe, 1);

    args[0] = command;
    args[1] = payload;
    args[2] = NULL;

    options.exit_cb = child_exit;
    options.file = args[0];
    options.args = args;
 
    options.stdio_count = 3;
    child_stdio[0].flags = UV_IGNORE;
    child_stdio[1].flags = UV_CREATE_PIPE | UV_WRITABLE_PIPE;
    child_stdio[1].data.stream = (uv_stream_t*) &out_pipe; 
    child_stdio[2].flags = UV_CREATE_PIPE | UV_WRITABLE_PIPE;
    child_stdio[2].data.stream = (uv_stream_t*) &err_pipe;
    options.stdio = child_stdio;

    ret = uv_spawn(loop, &child_req, options); 

    if (ret != 0)
    	printf("spawn failure. \n");

        uv_read_start((uv_stream_t*) &out_pipe, alloc_buffer, read_out);
        uv_read_start((uv_stream_t*) &err_pipe, alloc_buffer, read_err);

        uv_run(loop, UV_RUN_DEFAULT); 
}