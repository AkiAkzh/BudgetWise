import logging

def init_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.hasHandlers():
        console_handler = logging.StreamHandler()
        formatter = logging.Formatter("%(levelname)s:     %(asctime)s - %(message)s")
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
