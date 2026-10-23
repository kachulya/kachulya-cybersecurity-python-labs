VARIANT_NUMBER: int = 9
APP_TITLE: str = "Облік часу опрацювання повідомлень"
APP_DESCRIPTION: str = (
    "Сервіс обліку тривалості перевірки повідомлень про події безпеки (Варіант 9). "
    "Категорія визначає джерело повідомлення (siem, helpdesk, monitoring), "
    "value — тривалість опрацювання у хвилинах (minutes), "
    "status — стан перевірки вимірювання (new, in_progress, done). "
    "Порогове значення тривалості: 15.0 хв."
)

UNIT: str = "minutes"
THRESHOLD: float = 15.0
MIN_VALUE: float = 0.0
MAX_VALUE: float = 1.7976931348623157e308

ALLOWED_CATEGORIES: tuple[str, ...] = ("siem", "helpdesk", "monitoring")
RECORD_TITLE_PREFIX: str = "Вимірювання опрацювання"
