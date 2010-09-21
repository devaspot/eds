-module(eds).
-author('Maxim Sokhatsky <maxim@synrc.com>').
-export([start/0]).                                                              
-compile(export_all).
-include("LDAP.hrl").
-define(TCP_OPTIONS, [binary, {packet, 0}, {active, false}, {reuseaddr, true}]).

start() ->
	listen(389).

listen(Port) ->
	{ok, LSocket} = gen_tcp:listen(Port, ?TCP_OPTIONS),
	accept(LSocket).
	                                     
accept(LSocket) ->
	{ok, Socket} = gen_tcp:accept(LSocket),
	spawn(fun() -> loop(Socket) end),
	accept(LSocket).

loop(Socket) ->
	case gen_tcp:recv(Socket, 0) of
		{ok, Data} ->
			Decoded = asn1rt:decode('LDAP','LDAPMessage',Data),
			case Decoded of
				{ok,{'LDAPMessage',No,Message,Asn}} -> message(No,Message,Socket);
				_Else -> noLDAP
			end,
			loop(Socket);
		{error, closed} ->
			ok
	end.

message(No,Message,Socket) ->
	io:format("messageID: ~p~n",[No]),
	io:format("~p~n",[Message]),
	case Message of

		{bindRequest, {'BindRequest',Type,Uid,Auth}} -> 

									bind(No,Uid,Auth,Socket);
   
		{searchRequest,	{'SearchRequest',SearchDN,Scope,Deref,SizeLimit,
			TimeLimit,TypesOnly,Filter,Attributes}} -> 

									search(No, SearchDN, Scope,Deref,SizeLimit,
										TimeLimit,TypesOnly, Filter,Attributes,Socket);

		{abandonRequest,Type} -> 
									abandon(No,Socket);

		_Else -> 
			{Msg, Body} = Message,
			unknown(Msg,Socket)
	end.

answer(Response,No,ProtocolOp,Socket) ->
	Message = #'LDAPMessage'{messageID = No, protocolOp = {ProtocolOp, Response}},
	{ok, Bytes} = asn1rt:encode('LDAP', 'LDAPMessage', Message),
	io:format("~p~n", [Message]),
	gen_tcp:send(Socket, list_to_binary(Bytes)).

bind(No,Uid,Auth,Socket) ->
	Response = #'BindResponse'{resultCode = success, matchedDN = Uid, diagnosticMessage = "OK"},
	answer(Response,No,bindResponse,Socket).

search(No,SearchDN,Scope,Deref,SizeLimit,TimeLimit,TypesOnly,Filter,Attributes,Socket) ->
	CN = #'PartialAttribute'{type = "cn", vals = ["Oleg Smirnov"]},
	Email = #'PartialAttribute'{type = "email", vals = [value = "oleg.smirnov@gmail.com"]},
	Response = #'SearchResultEntry'{
		objectName = "cn=Oleg Smirnov,ou=Contacts,uid=mes,ou=People,dc=eba,dc=li",
		attributes = [CN,Email]
	},
	answer(Response,No,searchResEntry,Socket),
	Done = #'LDAPResult'{resultCode = success, matchedDN = SearchDN, diagnosticMessage = "OK"},
	answer(Done,No,searchResDone,Socket).

abandon(No,Socket) ->
	gen_tcp:close(Socket).

unknown(Message,Socket) ->
	case Message of
		{Msg, Data} -> io:format("Unknown message ~p~n", [Msg])
	end.
