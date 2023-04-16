package app.utils;

import java.util.Arrays;
import java.util.Random;

public class RandomUniquePicker {
    public static String[] pick(String[] items, int n) {
        if (n > items.length) {
            return items;
        }

        Random random = new Random();

        // Shuffle the array using the Fisher-Yates shuffle algorithm
        for (int i = items.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            String temp = items[i];
            items[i] = items[j];
            items[j] = temp;
        }

        // Select the first n items of the shuffled array
        String[] result = Arrays.copyOfRange(items, 0, n);

        return result;
    }
}
