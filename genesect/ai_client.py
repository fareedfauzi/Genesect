# -*- coding: utf-8 -*-
"""
AI client for Genesect - handles communication with AI providers.
"""

import threading
import functools
import time
import contextlib
import importlib
import io
import warnings
import itertools

import ida_kernwin

from genesect.qt_compat import openai, httpx, anthropic, genai, gemini_backend
from genesect.config import CONFIG, LOGGER
from genesect.provider_config import profile_from_config, request_options_from_config


# Global state for UI to check
_ai_busy_count = 0
AI_CANCEL_REQUESTED = False
_REQUEST_IDS = itertools.count(1)
_BUSY_LOCK = threading.Lock()

_CONTEXT_LIMIT_ERROR_MARKERS = (
    "context length",
    "context window",
    "maximum context",
    "trying to keep the first",
    "prompt is too long",
    "context_length_exceeded",
    "too many tokens",
)


def _format_provider_error(provider, model, request_id, error):
    """Build a clear IDA Output diagnostic for a failed provider request."""
    detail = str(error).strip() or type(error).__name__
    normalized = detail.lower()
    context_limit = any(marker in normalized for marker in _CONTEXT_LIMIT_ERROR_MARKERS)
    category = "MODEL CONTEXT ERROR" if context_limit else "AI PROVIDER ERROR"
    explanation = (
        "The model server rejected the prompt because it exceeds the model's loaded "
        "context window. This is not a Genesect plugin failure."
        if context_limit else
        "The request failed while communicating with the configured AI provider."
    )
    return (
        f"\n[Genesect] [{category}] Request {request_id}\n"
        f"  Provider: {provider}\n"
        f"  Model: {model or '<not configured>'}\n"
        f"  Explanation: {explanation}\n"
        f"  Provider details: {detail}\n"
    )


def _quiet_optional_import(module_name):
    """Import an optional provider without leaking its dependency diagnostics."""
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=r'Field "model_(?:id|name)" has conflict with protected namespace.*',
            category=UserWarning,
        )
        # Some provider discovery code prints missing optional integrations
        # directly instead of reporting them through Python's warning system.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return importlib.import_module(module_name)


def _load_anthropic():
    global anthropic
    if anthropic is None:
        try:
            anthropic = _quiet_optional_import("anthropic")
        except ImportError:
            return None
    return anthropic


def _load_gemini():
    global genai, gemini_backend
    if genai is not None:
        return genai
    try:
        genai = _quiet_optional_import("google.genai")
        gemini_backend = "google-genai"
    except ImportError:
        try:
            genai = _quiet_optional_import("google.generativeai")
            gemini_backend = "google-generativeai"
        except ImportError:
            genai = None
            gemini_backend = None
    return genai

class AIBusyStatus:
    def __bool__(self):
        return _ai_busy_count > 0
    def __int__(self):
        return _ai_busy_count
    def __repr__(self):
        return str(_ai_busy_count > 0)
    def __eq__(self, other):
        if isinstance(other, bool):
            return (_ai_busy_count > 0) == other
        return super().__eq__(other)

AI_BUSY = AIBusyStatus()

class SimpleAI:
    def __init__(self, config):
        self.config = config
        self.provider = "openai"
        self.client = None
        self.async_func = None
        self.profile = profile_from_config(config)
        self.request_options = request_options_from_config(config)
        self._request_lock = threading.Lock()
        self._cancelled_requests = set()

        self.determine_provider()
        self.init_client()

    def cancel_request(self, request_id):
        with self._request_lock:
            self._cancelled_requests.add(int(request_id))

    def _request_cancelled(self, request_id):
        with self._request_lock:
            return int(request_id) in self._cancelled_requests

    def determine_provider(self):
        self.profile = profile_from_config(self.config)
        self.provider = self.profile.client_name
        LOGGER.log(f"AI provider selected: {self.profile.name}")

    def log_provider_info(self):
        info = f"Active AI Provider: {self.profile.name} (model: {self.profile.model}"
        if self.profile.url:
            info += f", URL: {self.profile.url}"
        info += ")"
        LOGGER.log(info)

    def init_client(self):
        if httpx is None:
            LOGGER.log("httpx is unavailable; AI client initialization skipped.")
            return
        read_timeout = float(self.request_options.timeout_seconds)
        timeout = httpx.Timeout(connect=min(15.0, read_timeout), read=read_timeout, write=30.0, pool=10.0)
        http_client = httpx.Client(proxy=self.config.proxy, timeout=timeout) if self.config.proxy else httpx.Client(timeout=timeout)

        # Helper to clean URLs
        def clean_url(u):
            if not u: return u
            u = u.strip()
            if u.endswith('/'): u = u[:-1]
            return u

        if self.provider == "openai":
            if not openai or not self.profile.key: return
            self.client = openai.OpenAI(api_key=self.profile.key, base_url=clean_url(self.profile.url), http_client=http_client)

        elif self.provider == "deepseek":
            if not openai or not self.profile.key: return
            self.client = openai.OpenAI(api_key=self.profile.key, base_url=clean_url(self.profile.url), http_client=http_client)

        elif self.provider == "ollama":
            if not openai: return
            self.client = openai.OpenAI(api_key="ollama", base_url=clean_url(self.profile.url), http_client=http_client)

        elif self.provider == "lmstudio":
            if not openai: return
            self.client = openai.OpenAI(api_key=self.profile.key or "lm-studio", base_url=clean_url(self.profile.url), http_client=http_client)

        elif self.provider == "custom":
            if not openai: return
            self.client = openai.OpenAI(api_key=self.profile.key or "not-required", base_url=clean_url(self.profile.url), http_client=http_client)

        elif self.provider == "anthropic":
            anthropic_sdk = _load_anthropic()
            if not anthropic_sdk or not self.profile.key:
                LOGGER.log("Anthropic library or Key missing.")
                return
            self.client = anthropic_sdk.Anthropic(api_key=self.profile.key, base_url=clean_url(self.profile.url), http_client=http_client)

        elif self.provider == "gemini":
            gemini_sdk = _load_gemini()
            if not gemini_sdk or not self.profile.key:
                LOGGER.log("Google GenAI library or Key missing.")
                return
            if gemini_backend == "google-genai":
                self.client = gemini_sdk.Client(api_key=self.profile.key)
            else:
                gemini_sdk.configure(api_key=self.profile.key)
                self.client = "gemini_configured"

    def query_model_async(self, prompt, callback, additional_options=None, on_chunk=None, on_status=None):
        """
        Query AI model asynchronously. 
        on_chunk(text) is called for each streamed part if streaming is supported.
        on_status(count, text) is called for status updates.
        callback(response, finish_reason) is called when finished.
        """
        global AI_BUSY, AI_CANCEL_REQUESTED, _ai_busy_count
        request_id = next(_REQUEST_IDS)
        with _BUSY_LOCK:
            if _ai_busy_count == 0:
                AI_CANCEL_REQUESTED = False
        if additional_options is None:
            additional_options = {}
        else:
            additional_options = dict(additional_options)
        additional_options.setdefault("max_completion_tokens", self.request_options.max_completion_tokens)
        additional_options.setdefault("temperature", self.request_options.temperature)

        def request_cancelled():
            return AI_CANCEL_REQUESTED or self._request_cancelled(request_id)

        def invoke_callback(**payload):
            """Pass lifecycle metadata only when the callback accepts it."""
            import inspect
            try:
                base_func = callback.func if isinstance(callback, functools.partial) else callback
                signature = inspect.signature(base_func)
                has_kwargs = any(
                    parameter.kind == inspect.Parameter.VAR_KEYWORD
                    for parameter in signature.parameters.values()
                )
                if has_kwargs:
                    callback(**payload)
                else:
                    filtered = {key: value for key, value in payload.items() if key in signature.parameters}
                    callback(**filtered)
            except (TypeError, ValueError):
                callback(response=payload.get("response"))

        def call_with_retry(operation):
            attempts = self.request_options.retry_attempts + 1
            for attempt in range(attempts):
                try:
                    return operation()
                except Exception as exc:
                    message = str(exc).lower()
                    permanent = any(token in message for token in (
                        "401", "403", "unauthorized", "forbidden", "invalid api key",
                        "model not found", "404", "context length", "context window",
                        "maximum context", "trying to keep the first", "prompt is too long",
                        "context_length_exceeded", "too many tokens",
                    ))
                    if permanent or attempt >= attempts - 1 or request_cancelled():
                        raise
                    delay = self.request_options.retry_backoff_seconds * (2 ** attempt)
                    LOGGER.log(
                        f"AI request {request_id} retry {attempt + 1}/"
                        f"{self.request_options.retry_attempts} in {delay:.1f}s: {type(exc).__name__}"
                    )
                    if on_status:
                        safe_execute(lambda a=attempt + 1, d=delay: on_status(0, f"Retry {a} in {d:.1f}s..."))
                    if delay:
                        time.sleep(delay)

        def safe_execute(func):
            def wrapper():
                try:
                    func()
                except:
                    pass
                return False
            try:
                ida_kernwin.execute_ui_requests((wrapper,))
            except:
                pass

        def thread_target():
            global _ai_busy_count, AI_CANCEL_REQUESTED
            with _BUSY_LOCK:
                _ai_busy_count += 1
            full_content = ""
            finish_reason = "stop"
            
            try:
                LOGGER.log(f"Sending request to {self.provider} (Streaming: {on_chunk is not None})...")
                
                # Update UI that we are sending the request
                if on_status:
                    safe_execute(lambda: on_status(0, "Sending request..."))

                if self.provider in ["openai", "deepseek", "ollama", "lmstudio", "custom"]:
                    if not self.client: raise ValueError(f"Client for {self.provider} not initialized.")

                    if isinstance(prompt, list):
                        messages = prompt
                    else:
                        messages = [{"role": "user", "content": prompt}]
                    model = self.profile.model

                    valid_args = {"model": model, "messages": messages}
                    is_reasoning = any(x in model.lower() for x in ["o1", "o3", "r1", "gpt-5", "reasoner", "reasoning", "thought"])
                    
                    if "max_completion_tokens" in additional_options:
                         if is_reasoning:
                             valid_args["max_completion_tokens"] = additional_options["max_completion_tokens"]
                         else:
                             valid_args["max_tokens"] = additional_options["max_completion_tokens"]
                    
                    for k, v in additional_options.items():
                        if k == "max_completion_tokens": continue
                        if is_reasoning and k in ["temperature", "top_p", "response_format"]:
                            continue
                        valid_args[k] = v

                    if on_chunk:
                        valid_args["stream"] = True
                        stream = call_with_retry(lambda: self.client.chat.completions.create(**valid_args))
                        
                        buffer = ""
                        last_update = time.time()
                        
                        for chunk in stream:
                            if request_cancelled():
                                finish_reason = "cancelled"
                                break
                            
                            delta = chunk.choices[0].delta if chunk.choices else None
                            if not delta: continue
                            
                            content = getattr(delta, 'content', "") or ""
                            # Reasoning fallback for stream
                            reasoning = getattr(delta, 'reasoning_content', "") or getattr(delta, 'reasoning', "") or ""
                            if not content and reasoning: content = reasoning
                            
                            if content:
                                full_content += content
                                buffer += content
                                # Buffer updates to keep IDA thread responsive
                                if time.time() - last_update > 0.05 or len(buffer) > 100:
                                    def _do_update(txt=buffer): on_chunk(txt)
                                    safe_execute(_do_update)
                                    buffer = ""
                                    last_update = time.time()
                            
                            fin = getattr(chunk.choices[0], 'finish_reason', None)
                            if fin: finish_reason = fin
                        
                        # Flush remaining
                        if buffer:
                            def _flush_update(txt=buffer): on_chunk(txt)
                            safe_execute(_flush_update)
                    else:
                        response = call_with_retry(lambda: self.client.chat.completions.create(**valid_args))
                        msg = response.choices[0].message if response.choices else None
                        if msg:
                            full_content = getattr(msg, 'content', "") or ""
                            reasoning = getattr(msg, 'reasoning_content', "") or getattr(msg, 'reasoning', "") or ""
                            if not full_content.strip() and reasoning.strip(): full_content = reasoning
                            finish_reason = getattr(response.choices[0], 'finish_reason', 'stop')
                        else:
                            full_content = ""

                elif self.provider == "anthropic":
                     if not self.client: raise ValueError("Anthropic client not initialized.")
                     
                     if isinstance(prompt, list):
                         messages = prompt
                     else:
                         messages = [{"role": "user", "content": prompt}]
                         
                     max_toks = additional_options.get("max_completion_tokens", 4096)
                     if on_chunk:
                         stream_context = call_with_retry(lambda: self.client.messages.stream(
                             model=self.profile.model,
                             max_tokens=max_toks,
                             messages=messages
                         ))
                         with stream_context as stream:
                             buffer = ""
                             last_update = time.time()
                             for text in stream.text_stream:
                                 if request_cancelled():
                                     finish_reason = "cancelled"
                                     break
                                 full_content += text
                                 buffer += text
                                 if time.time() - last_update > 0.05 or len(buffer) > 100:
                                     def _do_update(txt=buffer): on_chunk(txt)
                                     safe_execute(_do_update)
                                     buffer = ""
                                     last_update = time.time()
                             if buffer:
                                 def _flush_update(txt=buffer): on_chunk(txt)
                                 safe_execute(_flush_update)
                             
                             msg = stream.get_final_message()
                             finish_reason = getattr(msg, 'stop_reason', 'stop')
                             if finish_reason == 'max_tokens': finish_reason = 'length'
                     else:
                        message = call_with_retry(lambda: self.client.messages.create(
                            model=self.profile.model,
                            max_tokens=max_toks,
                            messages=messages
                        ))
                        full_content = message.content[0].text if hasattr(message.content[0], 'text') else str(message.content[0])
                        finish_reason = getattr(message, 'stop_reason', 'stop')
                        if finish_reason == 'max_tokens': finish_reason = 'length'

                elif self.provider == "gemini":
                     if not self.client: raise ValueError("Gemini not configured.")
                     
                     generation_config = {}
                     if "max_completion_tokens" in additional_options:
                         generation_config["max_output_tokens"] = additional_options["max_completion_tokens"]
                     if "temperature" in additional_options:
                         generation_config["temperature"] = additional_options["temperature"]
                     if "top_p" in additional_options:
                         generation_config["top_p"] = additional_options["top_p"]

                     if gemini_backend == "google-genai":
                         if isinstance(prompt, list):
                             history = []
                             for m in prompt:
                                 role = m.get("role", "user")
                                 if role == "assistant": role = "model"
                                 if role == "system": continue 
                                 history.append({"role": role, "parts": [{"text": m.get("content", "")}]})
                             
                             chat = self.client.chats.create(model=self.profile.model, history=history[:-1])
                             last_message = history[-1]["parts"][0]["text"]
                             
                             if on_chunk:
                                 response_stream = call_with_retry(lambda: chat.send_message_stream(last_message, config=generation_config))
                                 buffer = ""
                                 last_update = time.time()
                                 for chunk in response_stream:
                                     if request_cancelled():
                                         finish_reason = "cancelled"
                                         break
                                     txt = chunk.text or ""
                                     full_content += txt
                                     buffer += txt
                                     if time.time() - last_update > 0.05 or len(buffer) > 100:
                                         ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                                         buffer = ""
                                         last_update = time.time()
                                     if chunk.candidates:
                                         fr = chunk.candidates[0].finish_reason
                                         if fr:
                                             if any(x in str(fr).upper() for x in ["MAX_TOKENS", "LENGTH"]):
                                                 finish_reason = "length"
                                             else:
                                                 finish_reason = "stop"
                                 if buffer:
                                     ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                             else:
                                 response = call_with_retry(lambda: chat.send_message(last_message, config=generation_config))
                                 full_content = response.text or ""
                                 try:
                                     fr = response.candidates[0].finish_reason
                                     if fr and any(x in str(fr).upper() for x in ["MAX_TOKENS", "LENGTH"]):
                                         finish_reason = "length"
                                     else:
                                         finish_reason = "stop"
                                 except:
                                     finish_reason = "stop"
                         else:
                             if on_chunk:
                                 response_stream = call_with_retry(lambda: self.client.models.generate_content_stream(
                                     model=self.profile.model,
                                     contents=prompt,
                                     config=generation_config
                                 ))
                                 buffer = ""
                                 last_update = time.time()
                                 for chunk in response_stream:
                                     if request_cancelled():
                                         finish_reason = "cancelled"
                                         break
                                     txt = chunk.text or ""
                                     full_content += txt
                                     buffer += txt
                                     if time.time() - last_update > 0.05 or len(buffer) > 100:
                                         ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                                         buffer = ""
                                         last_update = time.time()
                                     if chunk.candidates:
                                         fr = chunk.candidates[0].finish_reason
                                         if fr:
                                             if any(x in str(fr).upper() for x in ["MAX_TOKENS", "LENGTH"]):
                                                 finish_reason = "length"
                                             else:
                                                 finish_reason = "stop"
                                 if buffer:
                                     ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                             else:
                                 response = call_with_retry(lambda: self.client.models.generate_content(
                                     model=self.profile.model,
                                     contents=prompt,
                                     config=generation_config
                                 ))
                                 full_content = response.text or ""
                                 try:
                                     fr = response.candidates[0].finish_reason
                                     if fr and any(x in str(fr).upper() for x in ["MAX_TOKENS", "LENGTH"]):
                                         finish_reason = "length"
                                     else:
                                         finish_reason = "stop"
                                 except:
                                     finish_reason = "stop"
                     else:
                         model = genai.GenerativeModel(self.profile.model)
                         if isinstance(prompt, list):
                             history = []
                             for m in prompt:
                                 role = m.get("role", "user")
                                 if role == "assistant": role = "model"
                                 if role == "system": continue 
                                 history.append({"role": role, "parts": [m.get("content", "")]})
                             
                             chat = model.start_chat(history=history[:-1])
                             if on_chunk:
                                 response_stream = call_with_retry(lambda: chat.send_message(history[-1]["parts"][0], stream=True, generation_config=generation_config))
                                 buffer = ""
                                 last_update = time.time()
                                 for chunk in response_stream:
                                     if request_cancelled():
                                         finish_reason = "cancelled"
                                         break
                                     full_content += chunk.text
                                     buffer += chunk.text
                                     if time.time() - last_update > 0.05 or len(buffer) > 100:
                                         ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                                         buffer = ""
                                         last_update = time.time()
                                 if buffer:
                                     ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                                 
                                 try:
                                     fr = response_stream.last.candidates[0].finish_reason
                                     if fr == 2: finish_reason = "length"
                                     else: finish_reason = "stop"
                                 except: finish_reason = "stop"
                             else:
                                 response = call_with_retry(lambda: chat.send_message(history[-1]["parts"][0], generation_config=generation_config))
                                 full_content = response.text
                                 try:
                                     fr = response.candidates[0].finish_reason
                                     if fr == 2: finish_reason = "length"
                                     else: finish_reason = "stop"
                                 except: finish_reason = "stop"
                         else:
                             if on_chunk:
                                 response_stream = call_with_retry(lambda: model.generate_content(prompt, stream=True, generation_config=generation_config))
                                 buffer = ""
                                 last_update = time.time()
                                 for chunk in response_stream:
                                     if request_cancelled():
                                         finish_reason = "cancelled"
                                         break
                                     full_content += chunk.text
                                     buffer += chunk.text
                                     if time.time() - last_update > 0.05 or len(buffer) > 100:
                                         ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                                         buffer = ""
                                         last_update = time.time()
                                 if buffer:
                                     ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                                 
                                 try:
                                     fr = response_stream.last.candidates[0].finish_reason
                                     if fr == 2: finish_reason = "length"
                                     else: finish_reason = "stop"
                                 except: finish_reason = "stop"
                             else:
                                 response = call_with_retry(lambda: model.generate_content(prompt, generation_config=generation_config))
                                 full_content = response.text
                                 try:
                                     fr = response.candidates[0].finish_reason
                                     if fr == 2: finish_reason = "length"
                                     else: finish_reason = "stop"
                                 except: finish_reason = "stop"


                LOGGER.log(f"Received response from {self.provider} ({len(full_content)} chars, reason: {finish_reason}).")

                # Wrap callback to ensure we pass response AND finish_reason
                def wrapped_callback(resp, reason):
                    invoke_callback(response=resp, finish_reason=reason, request_id=request_id)

                def _final_call():
                    wrapped_callback(resp=full_content, reason=finish_reason)
                safe_execute(_final_call)
            except Exception as e:
                LOGGER.log(f"AI Error ({self.provider}): {e}")
                error_msg = str(e)
                err_str = error_msg.lower()
                is_throttle = any(x in err_str for x in ["429", "too many requests", "quota", "rate limit"])
                output_message = _format_provider_error(
                    self.profile.name,
                    self.profile.model,
                    request_id,
                    e,
                )
                safe_execute(lambda text=output_message: print(text))
                
                def _do_err():
                    invoke_callback(
                        response=None,
                        error_msg=error_msg,
                        is_throttle=is_throttle,
                        request_id=request_id,
                    )
                        
                safe_execute(_do_err)
            finally:
                with self._request_lock:
                    self._cancelled_requests.discard(request_id)
                with _BUSY_LOCK:
                    _ai_busy_count = max(0, _ai_busy_count - 1)

        thread = threading.Thread(target=thread_target, name=f"GenesectAI-{request_id}", daemon=True)
        thread.start()
        return request_id

    def test_connection(self):
        prompt = "Reply with exactly: pong"
        try:
            if self.provider in ["openai", "deepseek", "ollama", "lmstudio", "custom"]:
                if not self.client: return False, "Client not initialized."
                
                model = self.profile.model

                is_reasoning = any(x in model.lower() for x in ["o1", "o3", "r1", "gpt-5", "reasoner", "reasoning", "thought"])
                valid_args = {"model": model, "messages": [{"role": "user", "content": prompt}]}
                
                if is_reasoning:
                    valid_args["max_completion_tokens"] = 128
                else:
                    valid_args["max_tokens"] = 30
                    valid_args["temperature"] = 0

                response = self.client.chat.completions.create(**valid_args)
                
                if not response.choices:
                    LOGGER.log(f"Test Connection: No choices. Full response: {response}")
                    return False, f"Connected but API returned no choices. (Model: {model})"

                msg = response.choices[0].message
                content = getattr(msg, 'content', "") or ""
                reasoning = getattr(msg, 'reasoning_content', "") or getattr(msg, 'reasoning', "") or ""
                refusal = getattr(msg, 'refusal', None)

                # Any valid response with choices = connection works.
                # Empty content can be a model quirk (e.g. some o1/o3 variants) — still counts as success.
                if refusal:
                    return False, f"Connected but model refused request: {refusal}"

                finish_reason = getattr(response.choices[0], 'finish_reason', None)
                if content.strip() or reasoning.strip():
                    return True, f"Connection successful! Model: {model}"

                # Got a valid response object but empty content — still a live connection
                LOGGER.log(f"Test Connection: Got valid response with empty content (finish_reason={finish_reason}). "
                           f"Full message: {msg}")
                return True, (f"Connection successful! (Model '{model}' replied with empty content — "
                              f"this is normal for some reasoning models. finish_reason={finish_reason})")

            elif self.provider == "anthropic":
                if not self.client: return False, "Anthropic client not initialized."
                message = self.client.messages.create(
                    model=self.profile.model,
                    max_tokens=10,
                    messages=[{"role": "user", "content": prompt}]
                )
                return True, f"Connection successful!"

            elif self.provider == "gemini":
                if not self.client: return False, "Gemini not configured."
                model_name = self.profile.model
                if gemini_backend == "google-genai":
                    response = self.client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                    )
                else:
                    model = genai.GenerativeModel(model_name)
                    response = model.generate_content(prompt)
                return True, f"Connection successful!"

            return False, f"Unknown provider: {self.provider}"
        except Exception as e:
            return False, f"Connection Failed: {str(e)}"


# Module-level singleton
AI_CLIENT = None


def reload_ai_client(config):
    """Atomically rebuild the shared client from the latest saved settings.

    Construct the replacement before publishing it so a setup exception cannot
    discard a working session client. Existing in-flight requests retain their
    local reference to the old instance; subsequent requests use the new one.
    """
    global AI_CLIENT
    replacement = SimpleAI(config)
    AI_CLIENT = replacement
    LOGGER.log(
        "AI runtime refreshed: %s (model: %s)"
        % (replacement.profile.name, replacement.profile.model)
    )
    return replacement
