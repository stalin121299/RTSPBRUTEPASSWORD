# RTSPBRUTEPASSWORD
Чтобы подобрать пароль от rtsp камер(использовать в целях образование, ни я никто не несёт ответсвенность за применение этой программы) нужно ввести процент начало от 0 до 100, мин и макс число символов и вставить атрибуты вот таким образом username,realm,nonce,A2,response без пробелов,чтоб раздобыть A2 нужно ввести в генератор md5 атрибуты METHOD(с большими буквами):URI например(PLAY:/ch1/main/av_stream) без скопки сгенерировать md5 и это будет A2   , восстановление пароли выглядит таким образом    
A1 = MD5(username:realm:password)
A2 = MD5(method:uri)
response = MD5(A1:nonce:MD5(nonceCount:clientNonce:qop):A2)
в нашем случае 
response = MD5(A1:nonce::A2)
сначала создаёться хэш от a1 подставляя новый пароль , потом респонце из всего , если респонце не тот то второй третий пароль до тех пор пока не найдет одинаковый респонце, A2 фиксированный чтоб A2 ввести вставить нужно сгенерировать как я писал выше или онлайн 
