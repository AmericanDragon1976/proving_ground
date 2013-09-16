#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <json-c/json.h>
#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <signal.h>
#include <ctype.h>

int 
main(int argc, char **argv)
{
  struct event_base   *event_loop = event_base_new();
  int                 i = 1, port_int, len = 0;
  char				  host[16], name[100], *buffer = NULL;
  FILE                *fd = NULL;

  *fd = fdopen(config.txt, "r");

  if (fd = NULL)
  	exit(0);

  fseek(fd, 0, SEEK_END);
  len = ftell(fd);
  rewind(fd);
  buffer = malloc(len + 1);

  if (fread(buffer, 1, len, fd) != len){
  	fprintf(stderr, "error reading config.txt file.\n");
  	exit(1);
  }

  json_object *jobj      = json_tokener_parse(buffer);
  json_object *name_jobj = json_object_object_get(jobj, "name");
  json_object *host_jobj = json_object_object_get(jobj, "host");
  json_object *port_jobj = json_object_object_get(jobj, "port");

  strncpy(name, json_object_get_string(name_jobj), 100);
  strncpy(host, json_object_get_string(host_jobj), 16);
  port_int = json_object_get_int64(port_jobj);

  json_object_put(jobj);
  json_object_put(name_jobj);
  json_object_put(host_jobj);
  json_object_put(port_jobj);

  struct addrinfo 	*hints = NULL;
  sturct addrinfo   *server = NULL
  char              *port_string = malloc(7);
  sprintf(port_string, "%d", port_int);
  struct            *bev;

  hints->ai_family   = AF_INET;
  hints->ai_socktype = SOCK_STREAM;
  hints->ai_flags 	 = 0;
  hints->ai_protocol = 0;

  getaddrinfo(host, port_string, hints, &server);
    struct bufferevent *bev = bufferevent_socket_new;
	//start listener
	//accept connections
	//on read 
	//if servic = the one in the config file 
	  //sent name, host, and port
	//if not send "service not found"
	// continue untill EOF then exit
}