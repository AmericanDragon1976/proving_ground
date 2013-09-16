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

#define ip_address      "127.0.0.1"
#define port_num        4000
#define mode            1 // 1 - seige mode, 2 - keyboard input mode 


uv_loop_t       *loop;
uv_tcp_t        client_socket;
char            *data = NULL;
int             data_length = 0;
int             data_position = 0;
int             loop_iterations = 1;
bool            create_file = true;

/*
 * Call back creating buffer that libuv functions need. 
 */
uv_buf_t 
 alloc_buffer(uv_handle_t *handle, size_t suggested_size) 
{//printf("alloc buffer \n");
    return uv_buf_init((char*) malloc(suggested_size), suggested_size);             //FREE for this Malloc ?
}

/*
 * Assembles a responce for the client, from all the data a running process returned, in json format. 
 */
char* 
package_reply(int *len) 
{//printf("package_reply \n");
    char                        *reply, *prereply;
    struct json_object          *reply_json_object = json_object_new_object();
    char                        hook[20];
    int                         i = 0, j = 0;

    sprintf(hook, "%d", loop_iterations);
    struct json_object          *temp_payload_json_object = json_object_new_string(hook);

    if (create_file){
        strcpy(hook, "sandbox.Random_file");
        create_file = false;
    }
    else {
        strcpy(hook, "sandbox.Random_file"); //"hooky.test.removedir");
        create_file = true;
    }

    struct json_object          *temp_hook_json_object = json_object_new_string(hook);

    json_object_object_add (reply_json_object, "hook", temp_hook_json_object); 
    json_object_object_add (reply_json_object, "payload", temp_payload_json_object);

    *len = strlen(json_object_to_json_string(reply_json_object));
    prereply = (char *) malloc(*len);
    strcpy(prereply, json_object_to_json_string(reply_json_object)); //printf("reply: %s\n", reply);
    reply = (char *) malloc(*len + 4);

    for (i = 3; i >= 0; i--){
        reply[i] = ((char *) len)[i];
    }
    for (i = 4, j = 0;i < *len + 4; i++)
        reply[i] = prereply[j++];

    json_object_put(temp_hook_json_object); 
    json_object_put(temp_payload_json_object); 
    json_object_put(reply_json_object);
    free(prereply);

    return(reply);
}

/*
 * 
 */
void
on_write (uv_write_t *req, int status)
{//printf("on write \n");

    free(req);
    req = NULL;
    free(data);
    data = NULL;
    data_length = 0;
    data_position = 0;
    // TODO: verify memory management with libuv and json-c lib
}

/*
 * Determines if data recived froma  client is a new or continuing client request, parses data, updates client info. 
 */
void 
process_data(ssize_t nread, uv_buf_t buf)
{//printf("processing: %d\n", (int) buf.base); 
    if (nread < 0) return;

    int             i = 0, j = 0; 
    char*           num;

    num = (char *) &data_length;

    if (data_length == 0){ //printf("Reciving data length: ");
        for (i = 0; i < 4; i++)
            num[i] = buf.base[j++];
        data = (char *) malloc(data_length + 1);
        data[data_length] = '\0';
        i = 4;
    }

    for ( ; (data_position < data_length) && (i < nread); )
        data[data_position++] = buf.base[i++];
}

void 
on_read(uv_stream_t *client_conn, ssize_t nread, uv_buf_t buf)
{//printf("on read, nread: %d\n", (int) nread); 
    if (nread < 1){
        ;
    }
    else { //printf("data: %s \n", data);
        process_data(nread, buf); //printf("data len: %d, data pos: %d\n", data_length, data_position);
        if (data_position == data_length && data_position != 0){
            json_object         *jobj = json_tokener_parse(data);
            json_object         *exit_code = json_object_object_get(jobj, "exit_code");
            json_object         *std_out = json_object_object_get(jobj, "stdout");
            json_object         *std_err = json_object_object_get(jobj, "stderr");
            json_object         *returned_hook = json_object_object_get(jobj, "hook");
            char                *ec, *so, *se, *rh;

            ec = (char *) malloc(json_object_get_string_len(exit_code) + 1);
            strcpy(ec, json_object_get_string(exit_code));
            json_object_put(exit_code);
            so = (char *) malloc(json_object_get_string_len(std_out) + 1);
            strcpy(so, json_object_get_string(std_out));
            json_object_put(std_out);
            se = (char *) malloc(json_object_get_string_len(std_err) + 1);
            strcpy(se, json_object_get_string(std_err));
            json_object_put(std_err);
            rh = (char *) malloc(json_object_get_string_len(returned_hook) + 1);
            strcpy(rh, json_object_get_string(returned_hook));
            json_object_put(returned_hook);

            json_object_put(jobj);

            //printf("exit code: %s stdout: %s stderr: %s \nOrigional hook sent: %s\n", ec, so, se, rh);

            free(ec);
            free(so);
            free(se);
            free(rh);

            if (loop_iterations < 1000){
                if (loop_iterations++ % 100 == 0)
                    printf("Requests sent: %d \n", loop_iterations);

                int         len;
                char        *hook_data = package_reply(&len);
                uv_write_t  *hook = (uv_write_t *) malloc(sizeof(uv_write_t));
                uv_buf_t    hook_buffer;

                hook->data = (void*) hook_data;
                hook_buffer.len = len + 4;
                hook_buffer.base = hook_data;
                uv_write(hook, client_conn, &hook_buffer, 1, on_write);
            }
            else {
                exit(0);
            }
        }
    }
}

void 
on_connect(uv_connect_t* req, int status)
{//printf("on_connect \n");
    if (status < 0) {
        fprintf(stderr, "%s\n", uv_strerror(status));
        return;
    }
    else {
        printf("Connection established. status: %d\n", status);
    }

    uv_read_start((uv_stream_t*) &client_socket, alloc_buffer, on_read);

    int         len;
    char        *hook_data = package_reply(&len);
    uv_write_t  *hook = (uv_write_t *) malloc(sizeof(uv_write_t));
    uv_buf_t    hook_buffer;

    hook->data = (void*) hook_data;
    hook_buffer.len = len + 4;
    hook_buffer.base = hook_data;
    uv_write(hook, (uv_stream_t *) &client_socket, &hook_buffer, 1, on_write);
}

int 
main ()
{

    uv_connect_t            connect;
    struct sockaddr_in      dest = uv_ip4_addr(ip_address, port_num);

    loop = uv_loop_new();
    data = NULL;
    data_length = 0;
    data_position = 0;

    uv_tcp_init(loop, &client_socket);
    uv_tcp_connect(&connect, &client_socket, dest, on_connect);

    uv_run(loop, UV_RUN_DEFAULT); 
}

