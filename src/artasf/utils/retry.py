"""
Async retry decorator with exponential back-off.

Usage:
    from artasf.utils.retry import async_retry

    @async_retry(max_attempts=3, backoff_base=1.0)
    async def my_flaky_call() -> str:
        ...

    # Retry only on specific exceptions:
    @async_retry(max_attempts=3, exceptions=(httpx.TransportError,))
    async def fetch() -> bytes:
        ...
"""

from __future__ import annotations

import asyncio
import functools
from typing import Any, Callable, TypeVar, overload

from loguru import logger

F = TypeVar("F", bound=Callable[..., Any])


def async_retry(
    max_attempts: int = 3,
    backoff_base: float = 1.0,
    exceptions: tuple[type[BaseException], ...] = (Exception,),
) -> Callable[[F], F]:
    """
    Decorator that retries an async function on failure with exponential back-off.

    Args:
        max_attempts: Total number of attempts (1 = no retry).
        backoff_base: Base delay in seconds; doubled each attempt (1s, 2s, 4s …).
        exceptions:   Exception types that trigger a retry.  Others propagate immediately.

    Example delays for max_attempts=3, backoff_base=1.0:
        attempt 1 fails → sleep 1 s
        attempt 2 fails → sleep 2 s
        attempt 3 fails → raise
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exc: BaseException | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt == max_attempts:
                        break
                    delay = backoff_base * (2 ** (attempt - 1))
                    logger.debug(
                        "{} attempt {}/{} failed ({}), retrying in {:.1f}s",
                        func.__qualname__,
                        attempt,
                        max_attempts,
                        exc,
                        delay,
                    )
                    await asyncio.sleep(delay)
            raise last_exc  # type: ignore[misc]

        return wrapper  # type: ignore[return-value]

    return decorator
